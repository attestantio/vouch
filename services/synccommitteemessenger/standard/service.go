// Copyright © 2021 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package standard

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/services/synccommitteeaggregator"
	"github.com/attestantio/vouch/services/synccommitteemessenger"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
)

const (
	maxSlotDataRecordsBeforeCleanUp = 100
	minSlotDataRecordsToKeep        = 32
)

// Service is a beacon block attester.
type Service struct {
	monitor                           metrics.SyncCommitteeMessageMonitor
	processConcurrency                int64
	slotsPerEpoch                     uint64
	syncCommitteeSize                 uint64
	syncCommitteeSubnetCount          uint64
	targetAggregatorsPerSyncCommittee uint64
	chainTimeService                  chaintime.Service
	syncCommitteeAggregator           synccommitteeaggregator.Service
	validatingAccountsProvider        accountmanager.ValidatingAccountsProvider
	beaconBlockRootProvider           eth2client.BeaconBlockRootProvider
	syncCommitteeMessagesSubmitter    submitter.SyncCommitteeMessagesSubmitter
	syncCommitteeSelectionSigner      signer.SyncCommitteeSelectionSigner
	syncCommitteeRootSigner           signer.SyncCommitteeRootSigner
	slotDataRecords                   map[phase0.Slot]synccommitteemessenger.SlotData
	slotDataRecordsMu                 sync.Mutex
}

// module-wide log.
var log zerolog.Logger

// New creates a new sync committee messenger.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "synccommitteemessenger").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	specResponse, err := parameters.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	slotsPerEpoch, err := specUint64(spec, "SLOTS_PER_EPOCH")
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain SLOTS_PER_EPOCH from spec")
	}

	syncCommitteeSize, err := specUint64(spec, "SYNC_COMMITTEE_SIZE")
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain SYNC_COMMITTEE_SIZE from spec")
	}

	syncCommitteeSubnetCount, err := specUint64(spec, "SYNC_COMMITTEE_SUBNET_COUNT")
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain SYNC_COMMITTEE_SUBNET_COUNT from spec")
	}

	targetAggregatorsPerSyncCommittee, err := specUint64(spec, "TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE")
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE from spec")
	}

	s := &Service{
		monitor:                           parameters.monitor,
		processConcurrency:                parameters.processConcurrency,
		slotsPerEpoch:                     slotsPerEpoch,
		syncCommitteeSize:                 syncCommitteeSize,
		syncCommitteeSubnetCount:          syncCommitteeSubnetCount,
		targetAggregatorsPerSyncCommittee: targetAggregatorsPerSyncCommittee,
		chainTimeService:                  parameters.chainTimeService,
		syncCommitteeAggregator:           parameters.syncCommitteeAggregator,
		validatingAccountsProvider:        parameters.validatingAccountsProvider,
		beaconBlockRootProvider:           parameters.beaconBlockRootProvider,
		syncCommitteeMessagesSubmitter:    parameters.syncCommitteeMessagesSubmitter,
		syncCommitteeSelectionSigner:      parameters.syncCommitteeSelectionSigner,
		syncCommitteeRootSigner:           parameters.syncCommitteeRootSigner,
		slotDataRecords:                   make(map[phase0.Slot]synccommitteemessenger.SlotData),
	}

	return s, nil
}

// Prepare prepares in advance of a sync committee message.
func (s *Service) Prepare(ctx context.Context, data interface{}) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.synccommitteemessenger.standard").Start(ctx, "Prepare")
	defer span.End()
	started := time.Now()

	duty, ok := data.(*synccommitteemessenger.Duty)
	if !ok {
		s.monitor.SyncCommitteeMessagesCompleted(started, 0, len(duty.ValidatorIndices()), "failed")
		return errors.New("passed invalid data structure")
	}

	// Decide if we are an aggregator.
	for _, validatorIndex := range duty.ValidatorIndices() {
		subcommittees := make(map[uint64]bool)
		for _, contributionIndex := range duty.ContributionIndices()[validatorIndex] {
			subcommittee := uint64(contributionIndex) / (s.syncCommitteeSize / s.syncCommitteeSubnetCount)
			subcommittees[subcommittee] = true
		}
		for subcommittee := range subcommittees {
			isAggregator, sig, err := s.isAggregator(ctx, duty.Account(validatorIndex), duty.Slot(), subcommittee)
			if err != nil {
				return errors.Wrap(err, "failed to calculate if this is an aggregator")
			}
			if isAggregator {
				duty.SetAggregatorSubcommittees(validatorIndex, subcommittee, sig)
			}
		}
	}

	return nil
}

// Message generates and broadcasts sync committee messages for a slot.
// It returns a list of messages made.
func (s *Service) Message(ctx context.Context, data interface{}) ([]*altair.SyncCommitteeMessage, error) {
	ctx, span := otel.Tracer("attestantio.vouch.services.synccommitteemessenger.standard").Start(ctx, "Message")
	defer span.End()
	started := time.Now()

	duty, ok := data.(*synccommitteemessenger.Duty)
	if !ok {
		s.monitor.SyncCommitteeMessagesCompleted(started, 0, len(duty.ValidatorIndices()), "failed")
		return nil, errors.New("passed invalid data structure")
	}

	// Fetch the beacon block root.
	beaconBlockRootResponse, err := s.beaconBlockRootProvider.BeaconBlockRoot(ctx, &api.BeaconBlockRootOpts{
		Block: "head",
	})
	if err != nil {
		s.monitor.SyncCommitteeMessagesCompleted(started, duty.Slot(), len(duty.ValidatorIndices()), "failed")
		return nil, errors.Wrap(err, "failed to obtain beacon block root")
	}
	beaconBlockRoot := beaconBlockRootResponse.Data
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained beacon block root")
	s.syncCommitteeAggregator.SetBeaconBlockRoot(duty.Slot(), *beaconBlockRoot)

	// Sign in parallel.
	msgs := make([]*altair.SyncCommitteeMessage, 0, len(duty.ContributionIndices()))
	var msgsMu sync.Mutex
	validatorIndices := duty.ValidatorIndices()

	s.UpdateSyncCommitteeDataRecord(duty.Slot(), *beaconBlockRoot, duty.ContributionIndices())

	var wg sync.WaitGroup
	for i := range validatorIndices {
		wg.Add(1)
		go func(ctx context.Context,
			wg *sync.WaitGroup,
			i int,
		) {
			defer wg.Done()
			account := duty.Account(validatorIndices[i])
			if account == nil {
				log.Debug().Msg("Account nil; likely exited validator still in sync committee")
				return
			}
			sig, err := s.contribute(ctx, account, s.chainTimeService.SlotToEpoch(duty.Slot()), *beaconBlockRoot)
			if err != nil {
				log.Error().Err(err).Msg("Failed to sign sync committee message")
				return
			}
			log.Trace().Uint64("slot", uint64(duty.Slot())).Uint64("validator_index", uint64(validatorIndices[i])).Str("signature", fmt.Sprintf("%#x", sig)).Msg("Signed sync committee message")

			msg := &altair.SyncCommitteeMessage{
				Slot:            duty.Slot(),
				BeaconBlockRoot: *beaconBlockRoot,
				ValidatorIndex:  validatorIndices[i],
				Signature:       sig,
			}
			msgsMu.Lock()
			msgs = append(msgs, msg)
			msgsMu.Unlock()
		}(ctx, &wg, i)
	}
	wg.Wait()

	if err := s.syncCommitteeMessagesSubmitter.SubmitSyncCommitteeMessages(ctx, msgs); err != nil {
		log.Trace().Dur("elapsed", time.Since(started)).Err(err).Msg("Failed to submit sync committee messages")
		s.monitor.SyncCommitteeMessagesCompleted(started, duty.Slot(), len(msgs), "failed")
		return nil, errors.Wrap(err, "failed to submit sync committee messages")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted sync committee messages")
	s.monitor.SyncCommitteeMessagesCompleted(started, duty.Slot(), len(msgs), "succeeded")

	return msgs, nil
}

// UpdateSyncCommitteeDataRecord updates the internal map of slot to slot data used for the sync committee message.
func (s *Service) UpdateSyncCommitteeDataRecord(slot phase0.Slot, root phase0.Root, validatorToCommitteeIndex map[phase0.ValidatorIndex][]phase0.CommitteeIndex) {
	s.slotDataRecordsMu.Lock()
	s.slotDataRecords[slot] = synccommitteemessenger.SlotData{Root: root, ValidatorToCommitteeIndex: validatorToCommitteeIndex}
	s.slotDataRecordsMu.Unlock()
}

// GetDataUsedForSlot returns slot data recorded for the sync committee message for a given slot.
func (s *Service) GetDataUsedForSlot(slot phase0.Slot) (synccommitteemessenger.SlotData, bool) {
	root, found := s.slotDataRecords[slot]
	return root, found
}

// RemoveHistoricDataUsedForSlotValidation goes through the sync committee data stored for each slot and removes old slots.
func (s *Service) RemoveHistoricDataUsedForSlotValidation(currentSlot phase0.Slot) {
	// Only trigger if we have crossed threshold of max slot records to keep.
	if len(s.slotDataRecords) > maxSlotDataRecordsBeforeCleanUp {
		lowestSlotToKeep := currentSlot - minSlotDataRecordsToKeep
		s.slotDataRecordsMu.Lock()
		for slot := range s.slotDataRecords {
			if slot < lowestSlotToKeep {
				delete(s.slotDataRecords, slot)
			}
		}
		s.slotDataRecordsMu.Unlock()
	}
}

func (s *Service) contribute(ctx context.Context,
	account e2wtypes.Account,
	epoch phase0.Epoch,
	root phase0.Root,
) (
	phase0.BLSSignature,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.synccommitteemessenger.standard").Start(ctx, "contribute")
	defer span.End()
	sig, err := s.syncCommitteeRootSigner.SignSyncCommitteeRoot(ctx, account, epoch, root)
	if err != nil {
		return phase0.BLSSignature{}, err
	}
	return sig, err
}

func (s *Service) isAggregator(ctx context.Context, account e2wtypes.Account, slot phase0.Slot, subcommitteeIndex uint64) (bool, phase0.BLSSignature, error) {
	if account == nil {
		log.Debug().Msg("Account nil; likely exited validator still in sync committee")
		return false, phase0.BLSSignature{}, nil
	}

	modulo := s.syncCommitteeSize / s.syncCommitteeSubnetCount / s.targetAggregatorsPerSyncCommittee
	if modulo < 1 {
		modulo = 1
	}

	// Sign the slot.
	signature, err := s.syncCommitteeSelectionSigner.SignSyncCommitteeSelection(ctx, account, slot, subcommitteeIndex)
	if err != nil {
		return false, phase0.BLSSignature{}, errors.Wrap(err, "failed to sign the slot")
	}

	// Hash the signature.
	sigHash := sha256.New()
	n, err := sigHash.Write(signature[:])
	if err != nil {
		return false, phase0.BLSSignature{}, errors.Wrap(err, "failed to hash the slot signature")
	}
	if n != len(signature) {
		return false, phase0.BLSSignature{}, errors.New("failed to write all bytes of the slot signature to the hash")
	}
	hash := sigHash.Sum(nil)

	return binary.LittleEndian.Uint64(hash[:8])%modulo == 0, signature, nil
}

func specUint64(spec map[string]interface{}, item string) (uint64, error) {
	tmp, exists := spec[item]
	if !exists {
		return 0, fmt.Errorf("%s not found in spec", item)
	}
	val, ok := tmp.(uint64)
	if !ok {
		return 0, fmt.Errorf("%s of unexpected type", item)
	}
	return val, nil
}
