// Copyright © 2020 - 2024 Attestant Limited.
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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
)

// Service is an attestation aggregator.
type Service struct {
	log                            zerolog.Logger
	monitor                        metrics.Service
	targetAggregatorsPerCommittee  uint64
	slotsPerEpoch                  uint64
	validatingAccountsProvider     accountmanager.ValidatingAccountsProvider
	aggregateAttestationProvider   eth2client.AggregateAttestationProvider
	aggregateAttestationsSubmitter submitter.AggregateAttestationsSubmitter
	slotSelectionSigner            signer.SlotSelectionSigner
	aggregateAndProofSigner        signer.AggregateAndProofSigner
	chainTime                      chaintime.Service
}

// New creates a new attestation aggregator.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "attestationaggregator").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}

	specResponse, err := parameters.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	tmp, exists := spec["SLOTS_PER_EPOCH"]
	if !exists {
		return nil, errors.New("SLOTS_PER_EPOCH not found in spec")
	}
	slotsPerEpoch, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("SLOTS_PER_EPOCH of unexpected type")
	}

	tmp, exists = spec["TARGET_AGGREGATORS_PER_COMMITTEE"]
	if !exists {
		return nil, errors.New("TARGET_AGGREGATORS_PER_COMMITTEE not found in spec")
	}
	targetAggregatorsPerCommittee, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("TARGET_AGGREGATORS_PER_COMMITTEE of unexpected type")
	}

	s := &Service{
		log:                            log,
		monitor:                        parameters.monitor,
		targetAggregatorsPerCommittee:  targetAggregatorsPerCommittee,
		slotsPerEpoch:                  slotsPerEpoch,
		validatingAccountsProvider:     parameters.validatingAccountsProvider,
		aggregateAttestationProvider:   parameters.aggregateAttestationProvider,
		aggregateAttestationsSubmitter: parameters.aggregateAttestationsSubmitter,
		slotSelectionSigner:            parameters.slotSelectionSigner,
		aggregateAndProofSigner:        parameters.aggregateAndProofSigner,
		chainTime:                      parameters.chainTime,
	}

	return s, nil
}

// Aggregate aggregates the attestations for a given slot/committee combination.
func (s *Service) Aggregate(ctx context.Context, data interface{}) {
	ctx, span := otel.Tracer("attestantio.vouch.services.attestationaggregator.standard").Start(ctx, "Aggregate")
	defer span.End()
	started := time.Now()

	duty, ok := data.(*attestationaggregator.Duty)
	if !ok {
		s.log.Error().Msg("Passed invalid data structure")
		var startOfSlot *time.Time
		if s.chainTime != nil {
			t := s.chainTime.StartOfSlot(0)
			startOfSlot = &t
		}
		monitorAttestationAggregationCompleted(started, 0, "failed", startOfSlot)
		return
	}
	log := s.log.With().Uint64("slot", uint64(duty.Slot)).Str("attestation_data_root", fmt.Sprintf("%#x", duty.AttestationDataRoot)).Logger()
	log.Trace().Msg("Aggregating")

	// Obtain the aggregate attestation.
	aggregateAttestationResponse, err := s.aggregateAttestationProvider.AggregateAttestation(ctx, &api.AggregateAttestationOpts{
		Slot:                duty.Slot,
		AttestationDataRoot: duty.AttestationDataRoot,
	})
	var startOfSlot *time.Time
	if s.chainTime != nil {
		t := s.chainTime.StartOfSlot(duty.Slot)
		startOfSlot = &t
	}
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain aggregate attestation")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}
	aggregateAttestation := aggregateAttestationResponse.Data

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained aggregate attestation")

	// Fetch the validating account.
	epoch := phase0.Epoch(uint64(aggregateAttestation.Data.Slot) / s.slotsPerEpoch)
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, epoch, []phase0.ValidatorIndex{duty.ValidatorIndex})
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain proposing validator account")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}
	if len(accounts) != 1 {
		log.Error().Err(err).Msg("Unknown proposing validator account")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}
	account := accounts[duty.ValidatorIndex]
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained aggregating account")

	// Sign the aggregate attestation.
	aggregateAndProof := &phase0.AggregateAndProof{
		AggregatorIndex: duty.ValidatorIndex,
		Aggregate:       aggregateAttestation,
		SelectionProof:  duty.SlotSignature,
	}
	aggregateAndProofRoot, err := aggregateAndProof.HashTreeRoot()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate hash tree root of aggregate and proof")
	}
	sig, err := s.aggregateAndProofSigner.SignAggregateAndProof(ctx, account, duty.Slot, phase0.Root(aggregateAndProofRoot))
	if err != nil {
		log.Error().Err(err).Msg("Failed to sign aggregate and proof")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Signed aggregate attestation")

	// Submit the signed aggregate and proof.
	signedAggregateAndProofs := []*phase0.SignedAggregateAndProof{
		{
			Message:   aggregateAndProof,
			Signature: sig,
		},
	}
	if err := s.aggregateAttestationsSubmitter.SubmitAggregateAttestations(ctx, signedAggregateAndProofs); err != nil {
		log.Error().Err(err).Msg("Failed to submit aggregate and proof")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted aggregate attestation")

	frac := float64(aggregateAndProof.Aggregate.AggregationBits.Count()) /
		float64(aggregateAndProof.Aggregate.AggregationBits.Len())
	monitorAttestationAggregationCoverage(frac)
	monitorAttestationAggregationCompleted(started, duty.Slot, "succeeded", startOfSlot)
}

// IsAggregator reports if we are an attestation aggregator for a given validator/committee/slot combination.
func (s *Service) IsAggregator(ctx context.Context,
	validatorIndex phase0.ValidatorIndex,
	slot phase0.Slot,
	committeeSize uint64,
) (bool, phase0.BLSSignature, error) {
	ctx, span := otel.Tracer("attestantio.vouch.services.attestationaggregator.standard").Start(ctx, "IsAggregator")
	defer span.End()

	modulo := committeeSize / s.targetAggregatorsPerCommittee
	if modulo == 0 {
		// Modulo must be at least 1.
		modulo = 1
	}

	// Fetch the validator from the account manager.
	epoch := phase0.Epoch(uint64(slot) / s.slotsPerEpoch)
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, epoch, []phase0.ValidatorIndex{validatorIndex})
	if err != nil {
		return false, phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain validator")
	}
	if len(accounts) == 0 {
		return false, phase0.BLSSignature{}, fmt.Errorf("validator %d unknown", validatorIndex)
	}
	account := accounts[validatorIndex]

	// Sign the slot.
	signature, err := s.slotSelectionSigner.SignSlotSelection(ctx, account, slot)
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
