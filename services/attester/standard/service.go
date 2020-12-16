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
	"bytes"
	"context"
	"fmt"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is a beacon block attester.
type Service struct {
	monitor                    metrics.AttestationMonitor
	processConcurrency         int64
	slotsPerEpoch              uint64
	validatingAccountsProvider accountmanager.ValidatingAccountsProvider
	attestationDataProvider    eth2client.AttestationDataProvider
	attestationsSubmitter      submitter.AttestationsSubmitter
	beaconAttestationsSigner   signer.BeaconAttestationsSigner
}

// module-wide log.
var log zerolog.Logger

// New creates a new beacon block attester.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "attester").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	slotsPerEpoch, err := parameters.slotsPerEpochProvider.SlotsPerEpoch(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain slots per epoch")
	}

	s := &Service{
		monitor:                    parameters.monitor,
		processConcurrency:         parameters.processConcurrency,
		slotsPerEpoch:              slotsPerEpoch,
		validatingAccountsProvider: parameters.validatingAccountsProvider,
		attestationDataProvider:    parameters.attestationDataProvider,
		attestationsSubmitter:      parameters.attestationsSubmitter,
		beaconAttestationsSigner:   parameters.beaconAttestationsSigner,
	}

	return s, nil
}

// Attest carries out attestations for a slot.
// It returns a map of attestations made, keyed on the validator index.
func (s *Service) Attest(ctx context.Context, data interface{}) ([]*spec.Attestation, error) {
	started := time.Now()

	duty, ok := data.(*attester.Duty)
	if !ok {
		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
		return nil, errors.New("passed invalid data structure")
	}
	uints := make([]uint64, len(duty.ValidatorIndices()))
	for i := range duty.ValidatorIndices() {
		uints[i] = uint64(duty.ValidatorIndices()[i])
	}
	log := log.With().Uint64("slot", uint64(duty.Slot())).Uints64("validator_indices", uints).Logger()

	// Fetch the attestation data.
	attestationData, err := s.attestationDataProvider.AttestationData(ctx, duty.Slot(), duty.CommitteeIndices()[0])
	if err != nil {
		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
		return nil, errors.Wrap(err, "failed to obtain attestation data")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained attestation data")

	if attestationData.Slot != duty.Slot() {
		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
		return nil, fmt.Errorf("attestation request for slot %d returned data for slot %d", duty.Slot(), attestationData.Slot)
	}
	if attestationData.Source.Epoch > attestationData.Target.Epoch {
		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
		return nil, fmt.Errorf("attestation request for slot %d returned source epoch %d greater than target epoch %d", duty.Slot(), attestationData.Source.Epoch, attestationData.Target.Epoch)
	}
	if attestationData.Target.Epoch > spec.Epoch(uint64(duty.Slot())/s.slotsPerEpoch) {
		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
		return nil, fmt.Errorf("attestation request for slot %d returned target epoch %d greater than current epoch %d", duty.Slot(), attestationData.Target.Epoch, spec.Epoch(uint64(duty.Slot())/s.slotsPerEpoch))
	}

	// Fetch the validating accounts.
	validatingAccounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, spec.Epoch(uint64(duty.Slot())/s.slotsPerEpoch), duty.ValidatorIndices())
	if err != nil {
		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
		return nil, errors.New("failed to obtain attesting validator accounts")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained validating accounts")

	// Break the map in to two arrays.
	accountValidatorIndices := make([]spec.ValidatorIndex, 0, len(validatingAccounts))
	accountsArray := make([]e2wtypes.Account, 0, len(validatingAccounts))
	for index, account := range validatingAccounts {
		accountValidatorIndices = append(accountValidatorIndices, index)
		accountsArray = append(accountsArray, account)
	}

	// Set the per-validator information.
	validatorIndexToArrayIndexMap := make(map[spec.ValidatorIndex]int)
	for i := range duty.ValidatorIndices() {
		validatorIndexToArrayIndexMap[duty.ValidatorIndices()[i]] = i
	}
	committeeIndices := make([]spec.CommitteeIndex, len(validatingAccounts))
	validatorCommitteeIndices := make([]spec.ValidatorIndex, len(validatingAccounts))
	committeeSizes := make([]uint64, len(validatingAccounts))
	for i := range accountsArray {
		committeeIndices[i] = duty.CommitteeIndices()[validatorIndexToArrayIndexMap[accountValidatorIndices[i]]]
		validatorCommitteeIndices[i] = spec.ValidatorIndex(duty.ValidatorCommitteeIndices()[validatorIndexToArrayIndexMap[accountValidatorIndices[i]]])
		committeeSizes[i] = duty.CommitteeSize(committeeIndices[i])
	}

	attestations, err := s.attest(ctx,
		duty.Slot(),
		duty,
		accountsArray,
		accountValidatorIndices,
		committeeIndices,
		validatorCommitteeIndices,
		committeeSizes,
		attestationData,
		started,
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to attest")
		s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "failed")
	}

	return attestations, nil
}

func (s *Service) attest(
	ctx context.Context,
	slot spec.Slot,
	duty *attester.Duty,
	accounts []e2wtypes.Account,
	validatorIndices []spec.ValidatorIndex,
	committeeIndices []spec.CommitteeIndex,
	validatorCommitteeIndices []spec.ValidatorIndex,
	committeeSizes []uint64,
	data *spec.AttestationData,
	started time.Time,
) ([]*spec.Attestation, error) {

	// Sign the attestation for all validating accounts.
	uintCommitteeIndices := make([]uint64, len(committeeIndices))
	for i := range committeeIndices {
		uintCommitteeIndices[i] = uint64(committeeIndices[i])
	}
	accountsArray := make([]e2wtypes.Account, 0, len(accounts))
	accountsArray = append(accountsArray, accounts...)

	sigs, err := s.beaconAttestationsSigner.SignBeaconAttestations(ctx,
		accountsArray,
		duty.Slot(),
		committeeIndices,
		data.BeaconBlockRoot,
		data.Source.Epoch,
		data.Source.Root,
		data.Target.Epoch,
		data.Target.Root,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign beacon attestations")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Signed")

	// Create the attestations.
	zeroSig := spec.BLSSignature{}
	attestations := make([]*spec.Attestation, 0, len(sigs))
	for i := range sigs {
		if bytes.Equal(sigs[i][:], zeroSig[:]) {
			log.Warn().Msg("No signature for validator; not creating attestation")
			continue
		}
		aggregationBits := bitfield.NewBitlist(committeeSizes[i])
		aggregationBits.SetBitAt(uint64(validatorCommitteeIndices[i]), true)
		attestation := &spec.Attestation{
			AggregationBits: aggregationBits,
			Data: &spec.AttestationData{
				Slot:            duty.Slot(),
				Index:           committeeIndices[i],
				BeaconBlockRoot: data.BeaconBlockRoot,
				Source: &spec.Checkpoint{
					Epoch: data.Source.Epoch,
					Root:  data.Source.Root,
				},
				Target: &spec.Checkpoint{
					Epoch: data.Target.Epoch,
					Root:  data.Target.Root,
				},
			},
		}
		copy(attestation.Signature[:], sigs[i][:])
		attestations = append(attestations, attestation)
	}

	// Submit the attestations.
	if err := s.attestationsSubmitter.SubmitAttestations(ctx, attestations); err != nil {
		log.Warn().Err(err).Msg("Failed to submit attestations")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted attestations")
	s.monitor.AttestationsCompleted(started, len(duty.ValidatorIndices()), "succeeded")

	return attestations, nil
}
