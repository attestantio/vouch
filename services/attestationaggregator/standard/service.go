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
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/electra"
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
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
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
func (s *Service) Aggregate(ctx context.Context, duty *attestationaggregator.Duty) {
	ctx, span := otel.Tracer("attestantio.vouch.services.attestationaggregator.standard").Start(ctx, "Aggregate")
	defer span.End()
	started := time.Now()

	log := s.log.With().Uint64("slot", uint64(duty.Slot)).Str("attestation_data_root", fmt.Sprintf("%#x", duty.AttestationDataRoot)).Logger()
	log.Trace().Msg("Aggregating")

	// Obtain the aggregate attestation.
	aggregateAttestationResponse, err := s.aggregateAttestationProvider.AggregateAttestation(ctx, &api.AggregateAttestationOpts{
		Slot:                duty.Slot,
		AttestationDataRoot: duty.AttestationDataRoot,
	})

	startOfSlot := s.chainTime.StartOfSlot(duty.Slot)
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain aggregate attestation")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}
	aggregateAttestation := aggregateAttestationResponse.Data

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained aggregate attestation")

	// Fetch the validating account.
	aggregateAttestationData, err := aggregateAttestation.Data()
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain aggregate attestation data")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}
	epoch := phase0.Epoch(uint64(aggregateAttestationData.Slot) / s.slotsPerEpoch)
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
	versionedAggregateAndProof, err := createVersionedAggregateAndProof(duty, aggregateAttestation)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create versioned aggregate and proof")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}
	aggregateAndProofRoot, err := versionedAggregateAndProof.HashTreeRoot()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate hash tree root of aggregate and proof")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}
	sig, err := s.aggregateAndProofSigner.SignAggregateAndProof(ctx, account, duty.Slot, aggregateAndProofRoot)
	if err != nil {
		log.Error().Err(err).Msg("Failed to sign aggregate and proof")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Signed aggregate attestation")

	// Submit the signed aggregate and proof.
	signedAggregateAndProof, err := createVersionedSignedAggregateAndProof(versionedAggregateAndProof, sig)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create versioned signed aggregate and proof")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}

	signedAggregateOpts := &api.SubmitAggregateAttestationsOpts{
		Common:                   api.CommonOpts{},
		SignedAggregateAndProofs: []*spec.VersionedSignedAggregateAndProof{signedAggregateAndProof},
	}
	if err := s.aggregateAttestationsSubmitter.SubmitAggregateAttestations(ctx, signedAggregateOpts); err != nil {
		log.Error().Err(err).Msg("Failed to submit aggregate and proof")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted aggregate attestation")

	aggregationBits, err := aggregateAttestation.AggregationBits()
	if err != nil {
		log.Error().Err(err).Msg("Failed to retrieve aggregation bits")
		monitorAttestationAggregationCompleted(started, duty.Slot, "failed", startOfSlot)
		return
	}
	frac := float64(aggregationBits.Count()) / float64(aggregationBits.Len())
	monitorAttestationAggregationCoverage(frac)
	monitorAttestationAggregationCompleted(started, duty.Slot, "succeeded", startOfSlot)
}

func createVersionedAggregateAndProof(duty *attestationaggregator.Duty, aggregateAttestation *spec.VersionedAttestation) (*spec.VersionedAggregateAndProof, error) {
	switch aggregateAttestation.Version {
	case spec.DataVersionPhase0:
		if aggregateAttestation.Phase0 == nil {
			return nil, errors.New("no phase0 attestation")
		}
		aggregateAndProof := &phase0.AggregateAndProof{
			AggregatorIndex: duty.ValidatorIndex,
			Aggregate:       aggregateAttestation.Phase0,
			SelectionProof:  duty.SlotSignature,
		}
		versionedAggregateAndProof := &spec.VersionedAggregateAndProof{
			Version: aggregateAttestation.Version,
			Phase0:  aggregateAndProof,
		}
		return versionedAggregateAndProof, nil
	case spec.DataVersionAltair:
		if aggregateAttestation.Altair == nil {
			return nil, errors.New("no altair attestation")
		}
		aggregateAndProof := &phase0.AggregateAndProof{
			AggregatorIndex: duty.ValidatorIndex,
			Aggregate:       aggregateAttestation.Altair,
			SelectionProof:  duty.SlotSignature,
		}
		versionedAggregateAndProof := &spec.VersionedAggregateAndProof{
			Version: aggregateAttestation.Version,
			Altair:  aggregateAndProof,
		}
		return versionedAggregateAndProof, nil
	case spec.DataVersionBellatrix:
		if aggregateAttestation.Bellatrix == nil {
			return nil, errors.New("no bellatrix attestation")
		}
		aggregateAndProof := &phase0.AggregateAndProof{
			AggregatorIndex: duty.ValidatorIndex,
			Aggregate:       aggregateAttestation.Bellatrix,
			SelectionProof:  duty.SlotSignature,
		}
		versionedAggregateAndProof := &spec.VersionedAggregateAndProof{
			Version:   aggregateAttestation.Version,
			Bellatrix: aggregateAndProof,
		}
		return versionedAggregateAndProof, nil
	case spec.DataVersionCapella:
		if aggregateAttestation.Capella == nil {
			return nil, errors.New("no capella attestation")
		}
		aggregateAndProof := &phase0.AggregateAndProof{
			AggregatorIndex: duty.ValidatorIndex,
			Aggregate:       aggregateAttestation.Capella,
			SelectionProof:  duty.SlotSignature,
		}
		versionedAggregateAndProof := &spec.VersionedAggregateAndProof{
			Version: aggregateAttestation.Version,
			Capella: aggregateAndProof,
		}
		return versionedAggregateAndProof, nil
	case spec.DataVersionDeneb:
		if aggregateAttestation.Deneb == nil {
			return nil, errors.New("no deneb attestation")
		}
		aggregateAndProof := &phase0.AggregateAndProof{
			AggregatorIndex: duty.ValidatorIndex,
			Aggregate:       aggregateAttestation.Deneb,
			SelectionProof:  duty.SlotSignature,
		}
		versionedAggregateAndProof := &spec.VersionedAggregateAndProof{
			Version: aggregateAttestation.Version,
			Deneb:   aggregateAndProof,
		}
		return versionedAggregateAndProof, nil
	case spec.DataVersionElectra:
		if aggregateAttestation.Electra == nil {
			return nil, errors.New("no electra attestation")
		}
		aggregateAndProof := &electra.AggregateAndProof{
			AggregatorIndex: duty.ValidatorIndex,
			Aggregate:       aggregateAttestation.Electra,
			SelectionProof:  duty.SlotSignature,
		}
		versionedAggregateAndProof := &spec.VersionedAggregateAndProof{
			Version: aggregateAttestation.Version,
			Electra: aggregateAndProof,
		}
		return versionedAggregateAndProof, nil
	default:
		return &spec.VersionedAggregateAndProof{}, errors.New("unknown version")
	}
}

func createVersionedSignedAggregateAndProof(aggregateAndProof *spec.VersionedAggregateAndProof, sig phase0.BLSSignature) (*spec.VersionedSignedAggregateAndProof, error) {
	switch aggregateAndProof.Version {
	case spec.DataVersionPhase0:
		if aggregateAndProof.Phase0 == nil {
			return nil, errors.New("no phase0 aggregate and proof")
		}
		signedAggregateAndProof := &phase0.SignedAggregateAndProof{
			Message:   aggregateAndProof.Phase0,
			Signature: sig,
		}
		signedVersionedAggregateAndProof := &spec.VersionedSignedAggregateAndProof{
			Version: aggregateAndProof.Version,
			Phase0:  signedAggregateAndProof,
		}
		return signedVersionedAggregateAndProof, nil
	case spec.DataVersionAltair:
		if aggregateAndProof.Altair == nil {
			return nil, errors.New("no altair aggregate and proof")
		}
		signedAggregateAndProof := &phase0.SignedAggregateAndProof{
			Message:   aggregateAndProof.Altair,
			Signature: sig,
		}
		signedVersionedAggregateAndProof := &spec.VersionedSignedAggregateAndProof{
			Version: aggregateAndProof.Version,
			Altair:  signedAggregateAndProof,
		}
		return signedVersionedAggregateAndProof, nil
	case spec.DataVersionBellatrix:
		if aggregateAndProof.Bellatrix == nil {
			return nil, errors.New("no bellatrix aggregate and proof")
		}
		signedAggregateAndProof := &phase0.SignedAggregateAndProof{
			Message:   aggregateAndProof.Bellatrix,
			Signature: sig,
		}
		signedVersionedAggregateAndProof := &spec.VersionedSignedAggregateAndProof{
			Version:   aggregateAndProof.Version,
			Bellatrix: signedAggregateAndProof,
		}
		return signedVersionedAggregateAndProof, nil
	case spec.DataVersionCapella:
		if aggregateAndProof.Capella == nil {
			return nil, errors.New("no capella aggregate and proof")
		}
		signedAggregateAndProof := &phase0.SignedAggregateAndProof{
			Message:   aggregateAndProof.Capella,
			Signature: sig,
		}
		signedVersionedAggregateAndProof := &spec.VersionedSignedAggregateAndProof{
			Version: aggregateAndProof.Version,
			Capella: signedAggregateAndProof,
		}
		return signedVersionedAggregateAndProof, nil
	case spec.DataVersionDeneb:
		if aggregateAndProof.Deneb == nil {
			return nil, errors.New("no deneb aggregate and proof")
		}
		signedAggregateAndProof := &phase0.SignedAggregateAndProof{
			Message:   aggregateAndProof.Deneb,
			Signature: sig,
		}
		signedVersionedAggregateAndProof := &spec.VersionedSignedAggregateAndProof{
			Version: aggregateAndProof.Version,
			Deneb:   signedAggregateAndProof,
		}
		return signedVersionedAggregateAndProof, nil
	case spec.DataVersionElectra:
		if aggregateAndProof.Electra == nil {
			return nil, errors.New("no electra aggregate and proof")
		}
		signedAggregateAndProof := &electra.SignedAggregateAndProof{
			Message:   aggregateAndProof.Electra,
			Signature: sig,
		}
		signedVersionedAggregateAndProof := &spec.VersionedSignedAggregateAndProof{
			Version: aggregateAndProof.Version,
			Electra: signedAggregateAndProof,
		}
		return signedVersionedAggregateAndProof, nil
	default:
		return &spec.VersionedSignedAggregateAndProof{}, errors.New("unknown version")
	}
}

// AggregatorsAndSignatures reports signatures and whether validators are attestation aggregators for a given slot.
func (s *Service) AggregatorsAndSignatures(ctx context.Context,
	accounts []e2wtypes.Account,
	slot phase0.Slot,
	committeeSizes []uint64,
) ([]phase0.BLSSignature, []bool, error) {
	ctx, span := otel.Tracer("attestantio.vouch.services.attestationaggregator.standard").Start(ctx, "AggregatorsAndSignatures")
	defer span.End()

	// Sign the slots.
	sigs, err := s.slotSelectionSigner.SignSlotSelections(ctx, accounts, slot)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to sign the slots")
	}
	aggregators := make([]bool, len(sigs))
	for i, signature := range sigs {
		// Calculate modulo from the committee lengths.
		modulo := committeeSizes[i] / s.targetAggregatorsPerCommittee
		if modulo == 0 {
			// Modulo must be at least 1.
			modulo = 1
		}

		// Hash the signature.
		sigHash := sha256.New()
		n, err := sigHash.Write(signature[:])
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to hash the slot signature")
		}
		if n != len(signature) {
			return nil, nil, errors.New("failed to write all bytes of the slot signature to the hash")
		}
		hash := sigHash.Sum(nil)

		aggregators[i] = binary.LittleEndian.Uint64(hash[:8])%modulo == 0
	}
	return sigs, aggregators, nil
}
