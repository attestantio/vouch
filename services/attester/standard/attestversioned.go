// Copyright © 2025 Attestant Limited.
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
	"bytes"
	"context"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/go-bitfield"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// AttestVersioned carries out attestations for a slot.
// It returns a map of versioned attestations made, keyed on the validator index.
func (s *Service) AttestVersioned(ctx context.Context, duty *attester.Duty) ([]*spec.VersionedAttestation, error) {
	ctx, span := otel.Tracer("attestantio.vouch.services.attester.standard").Start(ctx, "Attest")
	defer span.End()
	started := time.Now()

	span.SetAttributes(attribute.Int64("slot", util.SlotToInt64(duty.Slot())))

	validatorIndices := s.fetchValidatorIndices(ctx, duty)

	// Fetch the attestation data.
	startOfSlot := s.chainTime.StartOfSlot(duty.Slot())
	attestationData, err := s.obtainAttestationData(ctx, duty)
	if err != nil {
		monitorAttestationsCompleted(started, duty.Slot(), len(validatorIndices), "failed", startOfSlot)
		return nil, err
	}

	if err := s.validateAttestationData(ctx, duty, attestationData); err != nil {
		monitorAttestationsCompleted(started, duty.Slot(), len(validatorIndices), "failed", startOfSlot)
		return nil, err
	}

	// Fetch the validating accounts.
	validatingAccounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, phase0.Epoch(uint64(duty.Slot())/s.slotsPerEpoch), validatorIndices)
	if err != nil {
		monitorAttestationsCompleted(started, duty.Slot(), len(validatorIndices), "failed", startOfSlot)
		return nil, errors.Wrap(err, "failed to obtain attesting validator accounts")
	}
	s.log.Trace().Dur("elapsed", time.Since(started)).Int("validating_accounts", len(validatingAccounts)).Msg("Obtained validating accounts")

	// Break the map into two arrays.
	accountValidatorIndices := make([]phase0.ValidatorIndex, 0, len(validatingAccounts))
	accountsArray := make([]e2wtypes.Account, 0, len(validatingAccounts))
	for index, account := range validatingAccounts {
		accountValidatorIndices = append(accountValidatorIndices, index)
		accountsArray = append(accountsArray, account)
	}

	// Set the per-validator information.
	validatorIndexToArrayIndexMap := make(map[phase0.ValidatorIndex]int)
	for i, index := range validatorIndices {
		validatorIndexToArrayIndexMap[index] = i
	}
	committeeIndices := make([]phase0.CommitteeIndex, len(validatingAccounts))
	validatorCommitteeIndices := make([]phase0.ValidatorIndex, len(validatingAccounts))
	committeeSizes := make([]uint64, len(validatingAccounts))
	for i := range accountsArray {
		committeeIndices[i] = duty.CommitteeIndices()[validatorIndexToArrayIndexMap[accountValidatorIndices[i]]]
		validatorCommitteeIndices[i] = phase0.ValidatorIndex(duty.ValidatorCommitteeIndices()[validatorIndexToArrayIndexMap[accountValidatorIndices[i]]])
		committeeSizes[i] = duty.CommitteeSize(committeeIndices[i])
	}

	attestations, err := s.attestVersioned(ctx,
		duty,
		accountsArray,
		committeeIndices,
		validatorCommitteeIndices,
		committeeSizes,
		attestationData,
		started,
	)
	if err != nil {
		monitorAttestationsCompleted(started, duty.Slot(), len(validatorIndices), "failed", startOfSlot)
		return nil, err
	}

	if len(attestations) < len(validatorIndices) {
		s.log.Error().Stringer("duty", duty).Int("total_attestations", len(validatorIndices)).Int("failed_attestations", len(validatorIndices)-len(attestations)).Msg("Some attestations failed")
		monitorAttestationsCompleted(started, duty.Slot(), len(validatorIndices)-len(attestations), "failed", startOfSlot)
	} else {
		monitorAttestationsCompleted(started, duty.Slot(), len(attestations), "succeeded", startOfSlot)
	}

	s.housekeepAttestedMap(ctx, duty)

	return attestations, nil
}

// attestVersioned carries out the internal work of attesting for versioned attestations.
func (s *Service) attestVersioned(
	ctx context.Context,
	duty *attester.Duty,
	accounts []e2wtypes.Account,
	committeeIndices []phase0.CommitteeIndex,
	validatorCommitteeIndices []phase0.ValidatorIndex,
	committeeSizes []uint64,
	data *phase0.AttestationData,
	started time.Time,
) ([]*spec.VersionedAttestation, error) {
	// Set the signing committee indices to use.
	signingCommitteeIndices := make([]phase0.CommitteeIndex, len(committeeIndices))
	for i := range signingCommitteeIndices {
		// Hardcode the committee indices to be 0 in Electra.
		signingCommitteeIndices[i] = 0
	}

	// Sign the attestation for all validating accounts.
	sigs, err := s.beaconAttestationsSigner.SignBeaconAttestations(ctx,
		accounts,
		duty.Slot(),
		signingCommitteeIndices,
		data.BeaconBlockRoot,
		data.Source.Epoch,
		data.Source.Root,
		data.Target.Epoch,
		data.Target.Root,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign beacon attestations")
	}
	s.log.Trace().Dur("elapsed", time.Since(started)).Msg("Signed")

	// Create the versioned electra attestations.
	attestations := s.createVersionedAttestations(ctx, duty, validatorCommitteeIndices, committeeSizes, data, sigs)
	if len(attestations) == 0 {
		s.log.Info().Msg("No signed versioned attestations; not submitting")
		return attestations, nil
	}

	// Submit the versioned attestations.
	submissionStarted := time.Now()
	opts := &api.SubmitAttestationsOpts{Attestations: attestations}
	if err := s.versionedAttestationsSubmitter.SubmitVersionedAttestations(ctx, opts); err != nil {
		return nil, errors.Wrap(err, "failed to submit versioned attestations")
	}
	s.log.Trace().Dur("elapsed", time.Since(started)).Dur("submission_elapsed", time.Since(submissionStarted)).Msg("Submitted versioned attestations")

	return attestations, nil
}

// createVersionedAttestations returns versioned attestations specifically for electra (index set to 0).
func (s *Service) createVersionedAttestations(_ context.Context,
	duty *attester.Duty,
	validatorCommitteeIndices []phase0.ValidatorIndex,
	committeeSizes []uint64,
	data *phase0.AttestationData,
	sigs []phase0.BLSSignature,
) []*spec.VersionedAttestation {
	zeroSig := phase0.BLSSignature{}
	attestations := make([]*spec.VersionedAttestation, 0, len(sigs))
	for i := range sigs {
		if bytes.Equal(sigs[i][:], zeroSig[:]) {
			s.log.Warn().Msg("No signature for validator; not creating attestation")
			continue
		}
		aggregationBits := bitfield.NewBitlist(committeeSizes[i])
		aggregationBits.SetBitAt(uint64(validatorCommitteeIndices[i]), true)

		committeeBits := bitfield.NewBitvector64()
		committeeBits.SetBitAt(uint64(validatorCommitteeIndices[i]), true)

		attestation := &electra.Attestation{
			AggregationBits: aggregationBits,
			Data: &phase0.AttestationData{
				Slot:            duty.Slot(),
				Index:           0, // Deprecated for now so fixed to 0.
				BeaconBlockRoot: data.BeaconBlockRoot,
				Source: &phase0.Checkpoint{
					Epoch: data.Source.Epoch,
					Root:  data.Source.Root,
				},
				Target: &phase0.Checkpoint{
					Epoch: data.Target.Epoch,
					Root:  data.Target.Root,
				},
			},
			CommitteeBits: committeeBits,
		}
		copy(attestation.Signature[:], sigs[i][:])
		versionedAttestation := &spec.VersionedAttestation{Version: spec.DataVersionElectra, Electra: attestation}
		attestations = append(attestations, versionedAttestation)
	}

	return attestations
}
