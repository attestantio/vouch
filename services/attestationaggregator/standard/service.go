// Copyright © 2020 Attestant Limited.
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
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is an attestation aggregator.
type Service struct {
	monitor                        metrics.AttestationAggregationMonitor
	targetAggregatorsPerCommittee  uint64
	slotsPerEpoch                  uint64
	validatingAccountsProvider     accountmanager.ValidatingAccountsProvider
	aggregateAttestationProvider   eth2client.AggregateAttestationProvider
	aggregateAttestationsSubmitter submitter.AggregateAttestationsSubmitter
	slotSelectionSigner            signer.SlotSelectionSigner
	aggregateAndProofSigner        signer.AggregateAndProofSigner
}

// module-wide log.
var log zerolog.Logger

// New creates a new attestation aggregator.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "attestationaggregator").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	targetAggregatorsPerCommittee, err := parameters.targetAggregatorsPerCommitteeProvider.TargetAggregatorsPerCommittee(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain target aggregators per committee")
	}
	slotsPerEpoch, err := parameters.slotsPerEpochProvider.SlotsPerEpoch(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain slots per epoch")
	}

	s := &Service{
		monitor:                        parameters.monitor,
		targetAggregatorsPerCommittee:  targetAggregatorsPerCommittee,
		slotsPerEpoch:                  slotsPerEpoch,
		validatingAccountsProvider:     parameters.validatingAccountsProvider,
		aggregateAttestationProvider:   parameters.aggregateAttestationProvider,
		aggregateAttestationsSubmitter: parameters.aggregateAttestationsSubmitter,
		slotSelectionSigner:            parameters.slotSelectionSigner,
		aggregateAndProofSigner:        parameters.aggregateAndProofSigner,
	}

	return s, nil
}

// Aggregate aggregates the attestations for a given slot/committee combination.
func (s *Service) Aggregate(ctx context.Context, data interface{}) {
	started := time.Now()

	duty, ok := data.(*attestationaggregator.Duty)
	if !ok {
		log.Error().Msg("Passed invalid data structure")
		s.monitor.AttestationAggregationCompleted(started, 0, "failed")
		return
	}
	log := log.With().Uint64("slot", uint64(duty.Slot)).Str("attestation_data_root", fmt.Sprintf("%#x", duty.AttestationDataRoot)).Logger()
	log.Trace().Msg("Aggregating")

	// Obtain the aggregate attestation.
	aggregateAttestation, err := s.aggregateAttestationProvider.AggregateAttestation(ctx, duty.Slot, duty.AttestationDataRoot)
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain aggregate attestation")
		s.monitor.AttestationAggregationCompleted(started, duty.Slot, "failed")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained aggregate attestation")
	if aggregateAttestation == nil {
		log.Debug().Msg("Obtained nil aggregate attestation")
		return
	}

	// Fetch the validating account.
	epoch := phase0.Epoch(uint64(aggregateAttestation.Data.Slot) / s.slotsPerEpoch)
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, epoch, []phase0.ValidatorIndex{duty.ValidatorIndex})
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain proposing validator account")
		s.monitor.AttestationAggregationCompleted(started, duty.Slot, "failed")
		return
	}
	if len(accounts) != 1 {
		log.Error().Err(err).Msg("Unknown proposing validator account")
		s.monitor.AttestationAggregationCompleted(started, duty.Slot, "failed")
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
		s.monitor.AttestationAggregationCompleted(started, duty.Slot, "failed")
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
		s.monitor.AttestationAggregationCompleted(started, duty.Slot, "failed")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted aggregate attestation")

	frac := float64(aggregateAndProof.Aggregate.AggregationBits.Count()) /
		float64(aggregateAndProof.Aggregate.AggregationBits.Len())
	s.monitor.AttestationAggregationCoverage(frac)
	s.monitor.AttestationAggregationCompleted(started, duty.Slot, "succeeded")
}

// IsAggregator reports if we are an attestation aggregator for a given validator/committee/slot combination.
func (s *Service) IsAggregator(ctx context.Context,
	validatorIndex phase0.ValidatorIndex,
	committeeIndex phase0.CommitteeIndex,
	slot phase0.Slot,
	committeeSize uint64,
) (bool, phase0.BLSSignature, error) {
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
		return false, phase0.BLSSignature{}, errors.New("validator unknown")
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
