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
	"encoding/json"
	"fmt"
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

// Attest carries out attestations for a slot.
// It returns a map of attestations made, keyed on the validator index.
func (s *Service) Attest(ctx context.Context, duty *attester.Duty) ([]*spec.VersionedAttestation, error) {
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

	attestations, err := s.attest(ctx,
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

	if len(attestations) == 0 {
		monitorAttestationsCompleted(started, duty.Slot(), len(validatorIndices), "failed", startOfSlot)
		return nil, errors.New("no attestations succeeded")
	}

	if len(attestations) < len(validatorIndices) {
		s.log.Error().Stringer("duty", duty).Int("total_attestations", len(validatorIndices)).Int("failed_attestations", len(validatorIndices)-len(attestations)).Msg("Some attestations failed")
		monitorAttestationsCompleted(started, duty.Slot(), len(validatorIndices)-len(attestations), "failed", startOfSlot)
	}
	monitorAttestationsCompleted(started, duty.Slot(), len(attestations), "succeeded", startOfSlot)

	s.housekeepAttestedMap(ctx, duty)

	return attestations, nil
}

// attest carries out the internal work of attesting.
func (s *Service) attest(
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
	copy(signingCommitteeIndices, committeeIndices)
	epoch := s.chainTime.SlotToEpoch(duty.Slot())
	if epoch >= s.electraForkEpoch {
		for i := range signingCommitteeIndices {
			// Hardcode the committee indices to be 0 in Electra.
			signingCommitteeIndices[i] = 0
		}
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
	var attestations []*spec.VersionedAttestation

	if epoch < s.electraForkEpoch {
		attestations = s.createAttestations(ctx, duty, accounts, committeeIndices, validatorCommitteeIndices, committeeSizes, data, sigs)
		if len(attestations) == 0 {
			s.log.Info().Msg("No signed attestations; not submitting")
			return attestations, nil
		}
	} else {
		attestations = s.createElectraAttestations(ctx, duty, accounts, committeeIndices, validatorCommitteeIndices, committeeSizes, data, sigs)
		if len(attestations) == 0 {
			s.log.Info().Msg("No signed attestations; not submitting")
			return attestations, nil
		}
	}
	// Submit the versioned attestations.
	submissionStarted := time.Now()
	opts := &api.SubmitAttestationsOpts{Attestations: attestations}
	if err := s.attestationsSubmitter.SubmitAttestations(ctx, opts); err != nil {
		return nil, errors.Wrap(err, "failed to submit versioned attestations")
	}
	s.log.Trace().Dur("elapsed", time.Since(started)).Dur("submission_elapsed", time.Since(submissionStarted)).Msg("Submitted versioned attestations")

	return attestations, nil
}

func (s *Service) createAttestations(_ context.Context,
	duty *attester.Duty,
	accounts []e2wtypes.Account,
	committeeIndices []phase0.CommitteeIndex,
	validatorCommitteeIndices []phase0.ValidatorIndex,
	committeeSizes []uint64,
	data *phase0.AttestationData,
	sigs []phase0.BLSSignature,
) []*spec.VersionedAttestation {
	// Create the attestations.
	attestations := make([]*spec.VersionedAttestation, 0, len(sigs))
	for i := range sigs {
		if sigs[i].IsZero() {
			s.log.Warn().
				Str("validator_pubkey", fmt.Sprintf("%#x", accounts[i].PublicKey().Marshal())).
				Msg("No signature for validator; not creating attestation")
			continue
		}
		aggregationBits := bitfield.NewBitlist(committeeSizes[i])
		aggregationBits.SetBitAt(uint64(validatorCommitteeIndices[i]), true)
		attestation := &phase0.Attestation{
			AggregationBits: aggregationBits,
			Data: &phase0.AttestationData{
				Slot:            duty.Slot(),
				Index:           committeeIndices[i],
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
		}
		copy(attestation.Signature[:], sigs[i][:])
		versionedAttestation := &spec.VersionedAttestation{Version: spec.DataVersionPhase0, Phase0: attestation}
		attestations = append(attestations, versionedAttestation)
	}

	return attestations
}

// createElectraAttestations returns versioned attestations specifically for electra (index set to 0).
func (s *Service) createElectraAttestations(_ context.Context,
	duty *attester.Duty,
	accounts []e2wtypes.Account,
	committeeIndices []phase0.CommitteeIndex,
	validatorCommitteeIndices []phase0.ValidatorIndex,
	committeeSizes []uint64,
	data *phase0.AttestationData,
	sigs []phase0.BLSSignature,
) []*spec.VersionedAttestation {
	attestations := make([]*spec.VersionedAttestation, 0, len(sigs))
	for i := range sigs {
		if sigs[i].IsZero() {
			s.log.Warn().
				Str("validator_pubkey", fmt.Sprintf("%#x", accounts[i].PublicKey().Marshal())).
				Msg("No signature for validator; not creating attestation")
			continue
		}
		aggregationBits := bitfield.NewBitlist(committeeSizes[i])
		aggregationBits.SetBitAt(uint64(validatorCommitteeIndices[i]), true)

		committeeBits := bitfield.NewBitvector64()
		committeeBits.SetBitAt(uint64(committeeIndices[i]), true)

		attestation := &electra.Attestation{
			AggregationBits: aggregationBits,
			Data: &phase0.AttestationData{
				Slot:            duty.Slot(),
				Index:           0, // Deprecated in electra so fixed to 0.
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

func (s *Service) fetchValidatorIndices(_ context.Context,
	duty *attester.Duty,
) []phase0.ValidatorIndex {
	epoch := s.chainTime.SlotToEpoch(duty.Slot())

	// Ensure that we have an attested map for this epoch.
	s.attestedMu.Lock()
	if _, exists := s.attested[epoch]; !exists {
		s.attested[epoch] = make(map[phase0.ValidatorIndex]struct{})
	}
	s.attestedMu.Unlock()

	// Filter the list of validator indices.
	validatorIndices := make([]phase0.ValidatorIndex, 0, len(duty.ValidatorIndices()))
	uints := make([]uint64, 0, len(duty.ValidatorIndices()))
	for i, index := range duty.ValidatorIndices() {
		s.attestedMu.Lock()
		if _, exists := s.attested[epoch][index]; exists {
			s.log.Warn().
				Uint64("slot", uint64(duty.Slot())).
				Int("array_index", i).
				Uint64("validator_index", uint64(index)).
				Msg("Validator already attested this epoch; not attesting again")
		} else {
			validatorIndices = append(validatorIndices, index)
			uints = append(uints, uint64(index))
			s.attested[epoch][index] = struct{}{}
		}
		s.attestedMu.Unlock()
	}

	s.log.Trace().
		Uint64("slot", uint64(duty.Slot())).
		Uints64("validator_indices", uints).
		Msg("Validating indices")

	return validatorIndices
}

func (s *Service) obtainAttestationData(ctx context.Context,
	duty *attester.Duty,
) (
	*phase0.AttestationData,
	error,
) {
	attestationDataResponse, err := s.attestationDataProvider.AttestationData(ctx, &api.AttestationDataOpts{
		Slot:           duty.Slot(),
		CommitteeIndex: duty.CommitteeIndices()[0],
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain attestation data")
	}
	attestationData := attestationDataResponse.Data
	if e := s.log.Trace(); e.Enabled() {
		data, err := json.Marshal(attestationData)
		if err == nil {
			e.RawJSON("data", data).Msg("Obtained attestation data")
		}
	}

	return attestationData, nil
}

func (s *Service) validateAttestationData(_ context.Context,
	duty *attester.Duty,
	attestationData *phase0.AttestationData,
) error {
	if attestationData.Slot != duty.Slot() {
		return fmt.Errorf("attestation request for slot %d returned data for slot %d", duty.Slot(), attestationData.Slot)
	}

	if attestationData.Source.Epoch > attestationData.Target.Epoch {
		return fmt.Errorf("attestation request for slot %d returned source epoch %d greater than target epoch %d", duty.Slot(), attestationData.Source.Epoch, attestationData.Target.Epoch)
	}

	dutyEpoch := phase0.Epoch(uint64(duty.Slot()) / s.slotsPerEpoch)
	if attestationData.Target.Epoch > dutyEpoch {
		return fmt.Errorf("attestation request for slot %d returned target epoch %d greater than current epoch %d", duty.Slot(), attestationData.Target.Epoch, phase0.Epoch(uint64(duty.Slot())/s.slotsPerEpoch))
	}

	return nil
}

func (s *Service) housekeepAttestedMap(_ context.Context,
	duty *attester.Duty,
) {
	// Housekeep attested map.
	epoch := s.chainTime.SlotToEpoch(duty.Slot())
	if epoch > 1 {
		s.attestedMu.Lock()
		delete(s.attested, epoch-2)
		s.attestedMu.Unlock()
	}
}
