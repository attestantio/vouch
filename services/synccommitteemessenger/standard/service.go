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
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/services/synccommitteemessenger"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
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
	validatingAccountsProvider        accountmanager.ValidatingAccountsProvider
	beaconBlockRootProvider           eth2client.BeaconBlockRootProvider
	syncCommitteeMessagesSubmitter    submitter.SyncCommitteeMessagesSubmitter
	syncCommitteeSelectionSigner      signer.SyncCommitteeSelectionSigner
	syncCommitteeRootSigner           signer.SyncCommitteeRootSigner
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

	spec, err := parameters.specProvider.Spec(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain spec")
	}

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

	targetAggregatorsPerSyncCommittee, err := specUint64(spec, "TARGET_AGGREGATORS_PER_SYNC_COMMITTEE")
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain TARGET_AGGREGATORS_PER_SYNC_COMMITTEE from spec")
	}

	s := &Service{
		monitor:                           parameters.monitor,
		processConcurrency:                parameters.processConcurrency,
		slotsPerEpoch:                     slotsPerEpoch,
		syncCommitteeSize:                 syncCommitteeSize,
		syncCommitteeSubnetCount:          syncCommitteeSubnetCount,
		targetAggregatorsPerSyncCommittee: targetAggregatorsPerSyncCommittee,
		chainTimeService:                  parameters.chainTimeService,
		validatingAccountsProvider:        parameters.validatingAccountsProvider,
		beaconBlockRootProvider:           parameters.beaconBlockRootProvider,
		syncCommitteeMessagesSubmitter:    parameters.syncCommitteeMessagesSubmitter,
		syncCommitteeSelectionSigner:      parameters.syncCommitteeSelectionSigner,
		syncCommitteeRootSigner:           parameters.syncCommitteeRootSigner,
	}

	return s, nil
}

// Prepare prepares in advance of a sync committee message.
func (s *Service) Prepare(ctx context.Context, data interface{}) error {
	started := time.Now()

	duty, ok := data.(*synccommitteemessenger.Duty)
	if !ok {
		s.monitor.SyncCommitteeMessagesCompleted(started, len(duty.ValidatorIndices()), "failed")
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
	started := time.Now()

	duty, ok := data.(*synccommitteemessenger.Duty)
	if !ok {
		s.monitor.SyncCommitteeMessagesCompleted(started, len(duty.ValidatorIndices()), "failed")
		return nil, errors.New("passed invalid data structure")
	}

	// Fetch the beacon block root.
	beaconBlockRoot, err := s.beaconBlockRootProvider.BeaconBlockRoot(ctx, "head")
	if err != nil {
		s.monitor.SyncCommitteeMessagesCompleted(started, len(duty.ValidatorIndices()), "failed")
		return nil, errors.Wrap(err, "failed to obtain beacon block root")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained beacon block root")

	//	if len(duty.Accounts()) == 0 {
	//		// Fetch the validating accounts.
	//		validatingAccounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, s.chainTimeService.SlotToEpoch(duty.Slot()), duty.ValidatorIndices())
	//		if err != nil {
	//			s.monitor.SyncCommitteeMessagesCompleted(started, len(duty.ValidatorIndices()), "failed")
	//			return nil, errors.New("failed to obtain attesting validator accounts")
	//		}
	//		log.Trace().Dur("elapsed", time.Since(started)).Int("validating_accounts", len(validatingAccounts)).Msg("Obtained validating accounts")
	//		duty.SetAccounts(validatingAccounts)
	//	}

	// Sign in parallel.
	msgs := make([]*altair.SyncCommitteeMessage, 0, len(duty.ContributionIndices()))
	validatorIndices := make([]phase0.ValidatorIndex, 0, len(duty.ContributionIndices()))
	for validatorIndex := range duty.ContributionIndices() {
		validatorIndices = append(validatorIndices, validatorIndex)
	}
	_, err = util.Scatter(len(duty.ContributionIndices()), func(offset int, entries int, mu *sync.RWMutex) (interface{}, error) {
		for i := offset; i < offset+entries; i++ {
			sig, err := s.contribute(ctx, duty.Account(validatorIndices[i]), s.chainTimeService.SlotToEpoch(duty.Slot()), *beaconBlockRoot)
			if err != nil {
				log.Error().Err(err).Msg("Failed to sign sync committee message")
				continue
			}
			log.Trace().Str("signature", fmt.Sprintf("%#x", sig)).Msg("Signed sync committee message")

			msg := &altair.SyncCommitteeMessage{
				Slot:            duty.Slot(),
				BeaconBlockRoot: *beaconBlockRoot,
				ValidatorIndex:  validatorIndices[i],
				Signature:       sig,
			}
			mu.Lock()
			msgs = append(msgs, msg)
			mu.Unlock()
		}
		return nil, nil
	})
	if err != nil {
		s.monitor.SyncCommitteeMessagesCompleted(started, len(msgs), "failed")
		log.Error().Err(err).Str("result", "failed").Msg("Failed to obtain committee messages")
	}

	if err := s.syncCommitteeMessagesSubmitter.SubmitSyncCommitteeMessages(ctx, msgs); err != nil {
		s.monitor.SyncCommitteeMessagesCompleted(started, len(msgs), "failed")
		return nil, errors.Wrap(err, "failed to submit sync committee messages")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted sync committee messages")

	return msgs, nil
}

func (s *Service) contribute(ctx context.Context,
	account e2wtypes.Account,
	epoch phase0.Epoch,
	root phase0.Root,
) (
	phase0.BLSSignature,
	error,
) {
	sig, err := s.syncCommitteeRootSigner.SignSyncCommitteeRoot(ctx, account, epoch, root)
	if err != nil {
		return phase0.BLSSignature{}, err
	}
	return sig, err
}

// // Attest carries out attestations for a slot.
// // It returns a map of attestations made, keyed on the validator index.
// func (s *Service) Attest(ctx context.Context, data interface{}) ([]*phase0.Attestation, error) {
// 	started := time.Now()
//
// 	duty, ok := data.(*attester.Duty)
// 	if !ok {
// 		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
// 		return nil, errors.New("passed invalid data structure")
// 	}
// 	uints := make([]uint64, len(duty.ValidatorIndices()))
// 	for i := range duty.ValidatorIndices() {
// 		uints[i] = uint64(duty.ValidatorIndices()[i])
// 	}
// 	log := log.With().Uint64("slot", uint64(duty.Slot())).Uints64("validator_indices", uints).Logger()
//
// 	// Fetch the attestation data.
// 	attestationData, err := s.attestationDataProvider.AttestationData(ctx, duty.Slot(), duty.CommitteeIndices()[0])
// 	if err != nil {
// 		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
// 		return nil, errors.Wrap(err, "failed to obtain attestation data")
// 	}
// 	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained attestation data")
//
// 	if attestationData.Slot != duty.Slot() {
// 		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
// 		return nil, fmt.Errorf("attestation request for slot %d returned data for slot %d", duty.Slot(), attestationData.Slot)
// 	}
// 	if attestationData.Source.Epoch > attestationData.Target.Epoch {
// 		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
// 		return nil, fmt.Errorf("attestation request for slot %d returned source epoch %d greater than target epoch %d", duty.Slot(), attestationData.Source.Epoch, attestationData.Target.Epoch)
// 	}
// 	if attestationData.Target.Epoch > phase0.Epoch(uint64(duty.Slot())/s.slotsPerEpoch) {
// 		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
// 		return nil, fmt.Errorf("attestation request for slot %d returned target epoch %d greater than current epoch %d", duty.Slot(), attestationData.Target.Epoch, phase0.Epoch(uint64(duty.Slot())/s.slotsPerEpoch))
// 	}
//
// 	// Fetch the validating accounts.
// 	validatingAccounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, phase0.Epoch(uint64(duty.Slot())/s.slotsPerEpoch), duty.ValidatorIndices())
// 	if err != nil {
// 		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
// 		return nil, errors.New("failed to obtain attesting validator accounts")
// 	}
// 	log.Trace().Dur("elapsed", time.Since(started)).Int("validating_accounts", len(validatingAccounts)).Msg("Obtained validating accounts")
//
// 	// Break the map in to two arrays.
// 	accountValidatorIndices := make([]phase0.ValidatorIndex, 0, len(validatingAccounts))
// 	accountsArray := make([]e2wtypes.Account, 0, len(validatingAccounts))
// 	for index, account := range validatingAccounts {
// 		accountValidatorIndices = append(accountValidatorIndices, index)
// 		accountsArray = append(accountsArray, account)
// 	}
//
// 	// Set the per-validator information.
// 	validatorIndexToArrayIndexMap := make(map[phase0.ValidatorIndex]int)
// 	for i := range duty.ValidatorIndices() {
// 		validatorIndexToArrayIndexMap[duty.ValidatorIndices()[i]] = i
// 	}
// 	committeeIndices := make([]phase0.CommitteeIndex, len(validatingAccounts))
// 	validatorCommitteeIndices := make([]phase0.ValidatorIndex, len(validatingAccounts))
// 	committeeSizes := make([]uint64, len(validatingAccounts))
// 	for i := range accountsArray {
// 		committeeIndices[i] = duty.CommitteeIndices()[validatorIndexToArrayIndexMap[accountValidatorIndices[i]]]
// 		validatorCommitteeIndices[i] = phase0.ValidatorIndex(duty.ValidatorCommitteeIndices()[validatorIndexToArrayIndexMap[accountValidatorIndices[i]]])
// 		committeeSizes[i] = duty.CommitteeSize(committeeIndices[i])
// 	}
//
// 	attestations, err := s.attest(ctx,
// 		duty.Slot(),
// 		duty,
// 		accountsArray,
// 		accountValidatorIndices,
// 		committeeIndices,
// 		validatorCommitteeIndices,
// 		committeeSizes,
// 		attestationData,
// 		started,
// 	)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Failed to attest")
// 		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
// 	}
//
// 	return attestations, nil
// }

// func (s *Service) attest(
// 	ctx context.Context,
// 	slot phase0.Slot,
// 	duty *attester.Duty,
// 	accounts []e2wtypes.Account,
// 	validatorIndices []phase0.ValidatorIndex,
// 	committeeIndices []phase0.CommitteeIndex,
// 	validatorCommitteeIndices []phase0.ValidatorIndex,
// 	committeeSizes []uint64,
// 	data *phase0.AttestationData,
// 	started time.Time,
// ) ([]*phase0.Attestation, error) {
//
// 	// Sign the attestation for all validating accounts.
// 	uintCommitteeIndices := make([]uint64, len(committeeIndices))
// 	for i := range committeeIndices {
// 		uintCommitteeIndices[i] = uint64(committeeIndices[i])
// 	}
// 	accountsArray := make([]e2wtypes.Account, 0, len(accounts))
// 	accountsArray = append(accountsArray, accounts...)
//
// 	sigs, err := s.beaconAttestationsSigner.SignBeaconAttestations(ctx,
// 		accountsArray,
// 		duty.Slot(),
// 		committeeIndices,
// 		data.BeaconBlockRoot,
// 		data.Source.Epoch,
// 		data.Source.Root,
// 		data.Target.Epoch,
// 		data.Target.Root,
// 	)
// 	if err != nil {
// 		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
// 		return nil, errors.Wrap(err, "failed to sign beacon attestations")
// 	}
// 	log.Trace().Dur("elapsed", time.Since(started)).Msg("Signed")
//
// 	// Create the attestations.
// 	zeroSig := phase0.BLSSignature{}
// 	attestations := make([]*phase0.Attestation, 0, len(sigs))
// 	for i := range sigs {
// 		if bytes.Equal(sigs[i][:], zeroSig[:]) {
// 			log.Warn().Msg("No signature for validator; not creating attestation")
// 			continue
// 		}
// 		aggregationBits := bitfield.NewBitlist(committeeSizes[i])
// 		aggregationBits.SetBitAt(uint64(validatorCommitteeIndices[i]), true)
// 		attestation := &phase0.Attestation{
// 			AggregationBits: aggregationBits,
// 			Data: &phase0.AttestationData{
// 				Slot:            duty.Slot(),
// 				Index:           committeeIndices[i],
// 				BeaconBlockRoot: data.BeaconBlockRoot,
// 				Source: &phase0.Checkpoint{
// 					Epoch: data.Source.Epoch,
// 					Root:  data.Source.Root,
// 				},
// 				Target: &phase0.Checkpoint{
// 					Epoch: data.Target.Epoch,
// 					Root:  data.Target.Root,
// 				},
// 			},
// 		}
// 		copy(attestation.Signature[:], sigs[i][:])
// 		attestations = append(attestations, attestation)
// 	}
//
// 	if len(attestations) == 0 {
// 		log.Info().Msg("No signed attestations; not submitting")
// 		return attestations, nil
// 	}
//
// 	// Submit the attestations.
// 	if err := s.attestationsSubmitter.SubmitAttestations(ctx, attestations); err != nil {
// 		s.monitor.AttestationsCompleted(started, len(attestations), "failed")
// 		return nil, errors.Wrap(err, "failed to submit attestations")
// 	}
// 	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted attestations")
// 	s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "succeeded")
//
// 	return attestations, nil
// }

func (s *Service) isAggregator(ctx context.Context, account e2wtypes.Account, slot phase0.Slot, subcommitteeIndex uint64) (bool, phase0.BLSSignature, error) {
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
