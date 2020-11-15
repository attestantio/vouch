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
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is a beacon block attester.
type Service struct {
	monitor                    metrics.AttestationMonitor
	processConcurrency         int64
	slotsPerEpoch              uint64
	validatingAccountsProvider accountmanager.ValidatingAccountsProvider
	attestationDataProvider    eth2client.AttestationDataProvider
	attestationSubmitter       submitter.AttestationSubmitter
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
		attestationSubmitter:       parameters.attestationSubmitter,
	}

	return s, nil
}

// Attest carries out attestations for a slot.
// It returns a map of attestations made, keyed on the validator index.
func (s *Service) Attest(ctx context.Context, data interface{}) ([]*spec.Attestation, error) {
	started := time.Now()

	duty, ok := data.(*attester.Duty)
	if !ok {
		s.monitor.AttestationCompleted(started, "failed")
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
		s.monitor.AttestationCompleted(started, "failed")
		return nil, errors.Wrap(err, "failed to obtain attestation data")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained attestation data")

	if attestationData.Slot != duty.Slot() {
		s.monitor.AttestationCompleted(started, "failed")
		return nil, fmt.Errorf("attestation request for slot %d returned data for slot %d", duty.Slot(), attestationData.Slot)
	}
	if attestationData.Source.Epoch > attestationData.Target.Epoch {
		s.monitor.AttestationCompleted(started, "failed")
		return nil, fmt.Errorf("attestation request for slot %d returned source epoch %d greater than target epoch %d", duty.Slot(), attestationData.Source.Epoch, attestationData.Target.Epoch)
	}
	if attestationData.Target.Epoch > spec.Epoch(uint64(duty.Slot())/s.slotsPerEpoch) {
		s.monitor.AttestationCompleted(started, "failed")
		return nil, fmt.Errorf("attestation request for slot %d returned target epoch %d greater than current epoch %d", duty.Slot(), attestationData.Target.Epoch, spec.Epoch(uint64(duty.Slot())/s.slotsPerEpoch))
	}

	// Fetch the validating accounts.
	accounts, err := s.validatingAccountsProvider.AccountsByIndex(ctx, duty.ValidatorIndices())
	if err != nil {
		s.monitor.AttestationCompleted(started, "failed")
		return nil, errors.New("failed to obtain attesting validator accounts")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained validating accounts")

	// Set the per-validator information.
	validatorIndexToArrayIndexMap := make(map[spec.ValidatorIndex]int)
	for i := range duty.ValidatorIndices() {
		validatorIndexToArrayIndexMap[duty.ValidatorIndices()[i]] = i
	}
	committeeIndices := make([]spec.CommitteeIndex, len(accounts))
	validatorCommitteeIndices := make([]spec.ValidatorIndex, len(accounts))
	committeeSizes := make([]uint64, len(accounts))
	for i := range accounts {
		validatorIndex, err := accounts[i].Index(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain validator index")
		}
		committeeIndices[i] = duty.CommitteeIndices()[validatorIndexToArrayIndexMap[validatorIndex]]
		validatorCommitteeIndices[i] = spec.ValidatorIndex(duty.ValidatorCommitteeIndices()[validatorIndexToArrayIndexMap[validatorIndex]])
		committeeSizes[i] = duty.CommitteeSize(committeeIndices[i])
	}

	attestations, err := s.attest(ctx,
		duty.Slot(),
		duty,
		accounts,
		committeeIndices,
		validatorCommitteeIndices,
		committeeSizes,
		attestationData,
		started,
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to attest")
	}

	return attestations, nil
}

// // Attest carries out attestations for a slot.
// // It returns a map of attestations made, keyed on the validator index.
// func (s *Service) Attest(ctx context.Context, data interface{}) ([]*spec.Attestation, error) {
// 	started := time.Now()
//
// 	duty, ok := data.(*attester.Duty)
// 	if !ok {
// 		s.monitor.AttestationCompleted(started, "failed")
// 		return nil, errors.New("passed invalid data structure")
// 	}
// 	log := log.With().Uint64("slot", uint64(duty.Slot())).Logger()
// 	log.Trace().Strs("duties", duty.Tuples()).Msg("Attesting")
//
// 	// Fetch the attestation data.
// 	attestationData, err := s.attestationDataProvider.AttestationData(ctx, duty.Slot(), duty.CommitteeIndices()[0])
// 	if err != nil {
// 		s.monitor.AttestationCompleted(started, "failed")
// 		return nil, errors.Wrap(err, "failed to obtain attestation data")
// 	}
// 	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained attestation data")
//
// 	if attestationData.Slot != duty.Slot() {
// 		s.monitor.AttestationCompleted(started, "failed")
// 		return nil, fmt.Errorf("attestation request for slot %d returned data for slot %d", duty.Slot(), attestationData.Slot)
// 	}
// 	if attestationData.Source.Epoch > attestationData.Target.Epoch {
// 		s.monitor.AttestationCompleted(started, "failed")
// 		return nil, fmt.Errorf("attestation request for slot %d returned source epoch %d greater than target epoch %d", duty.Slot(), attestationData.Source.Epoch, attestationData.Target.Epoch)
// 	}
// 	if attestationData.Target.Epoch > duty.Slot()/s.slotsPerEpoch {
// 		s.monitor.AttestationCompleted(started, "failed")
// 		return nil, fmt.Errorf("attestation request for slot %d returned target epoch %d greater than current epoch %d", duty.Slot(), attestationData.Target.Epoch, duty.Slot()/s.slotsPerEpoch)
// 	}
//
// 	// Fetch the validating accounts.
// 	accounts, err := s.validatingAccountsProvider.AccountsByIndex(ctx, duty.ValidatorIndices())
// 	if err != nil {
// 		s.monitor.AttestationCompleted(started, "failed")
// 		return nil, errors.New("failed to obtain attesting validator accounts")
// 	}
// 	log.Trace().Dur("elapsed", time.Since(started)).Strs("tuples", duty.Tuples()).Msg("Obtained validating accounts")
//
// 	// Run the attestations in parallel, up to a concurrency limit.
// 	validatorIndexToArrayIndexMap := make(map[spec.ValidatorIndex]int)
// 	for i := range duty.ValidatorIndices() {
// 		validatorIndexToArrayIndexMap[duty.ValidatorIndices()[i]] = i
// 	}
// 	sem := semaphore.NewWeighted(s.processConcurrency)
// 	var wg sync.WaitGroup
// 	for _, account := range accounts {
// 		wg.Add(1)
// 		go func(sem *semaphore.Weighted, wg *sync.WaitGroup, account accountmanager.ValidatingAccount, attestations *[]*spec.Attestation, attestationsMutex *sync.Mutex) {
// 				// TODO update to common code format.
// 			defer wg.Done()
// 			if err := sem.Acquire(ctx, 1); err != nil {
// 				log.Error().Err(err).Msg("Failed to acquire semaphore")
// 				return
// 			}
// 			defer sem.Release(1)
//
// 			validatorIndex, err := account.Index(ctx)
// 			if err != nil {
// 				log.Warn().Err(err).Msg("Failed to obtain validator index")
// 				return
// 			}
// 			log := log.With().Uint64("validator_index", uint64(validatorIndex)).Logger()
// 			attestation, err := s.attest(ctx,
// 				duty.Slot(),
// 				duty.CommitteeIndices()[validatorIndexToArrayIndexMap[validatorIndex]],
// 				duty.ValidatorCommitteeIndices()[validatorIndexToArrayIndexMap[validatorIndex]],
// 				duty.CommitteeSize(duty.CommitteeIndices()[validatorIndexToArrayIndexMap[validatorIndex]]),
// 				account,
// 				attestationData,
// 			)
// 			if err != nil {
// 				log.Warn().Err(err).Msg("Failed to attest")
// 				s.monitor.AttestationCompleted(started, "failed")
// 				return
// 			}
// 			log.Trace().Dur("elapsed", time.Since(started)).Msg("Attested")
// 			s.monitor.AttestationCompleted(started, "succeeded")
// 			attestationsMutex.Lock()
// 			*attestations = append(*attestations, attestation)
// 			attestationsMutex.Unlock()
// //	// Set the per-validator information.
// //	validatorIndexToArrayIndexMap := make(map[uint64]int)
// //	for i := range duty.ValidatorIndices() {
// //		validatorIndexToArrayIndexMap[duty.ValidatorIndices()[i]] = i
// //	}
// //	committeeIndices := make([]uint64, len(accounts))
// //	validatorCommitteeIndices := make([]uint64, len(accounts))
// //	committeeSizes := make([]uint64, len(accounts))
// //	for i := range accounts {
// //		validatorIndex, err := accounts[i].Index(ctx)
// //		if err != nil {
// //			return nil, errors.Wrap(err, "failed to obtain validator index")
// //		}
// //		committeeIndices[i] = duty.CommitteeIndices()[validatorIndexToArrayIndexMap[validatorIndex]]
// //		validatorCommitteeIndices[i] = duty.ValidatorCommitteeIndices()[validatorIndexToArrayIndexMap[validatorIndex]]
// //		committeeSizes[i] = duty.CommitteeSize(committeeIndices[i])
// //	}
//
// 	attestations, err := s.attest(ctx,
// 		slot,
// 		duty,
// 		accounts,
// 		committeeIndices,
// 		validatorCommitteeIndices,
// 		committeeSizes,
// 		attestationData,
// 		started,
// 	)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Failed to attest")
// 	}
// 	}
//
// 	return attestations, nil
// }

func (s *Service) attest(
	ctx context.Context,
	slot spec.Slot,
	duty *attester.Duty,
	accounts []accountmanager.ValidatingAccount,
	committeeIndices []spec.CommitteeIndex,
	validatorCommitteeIndices []spec.ValidatorIndex,
	committeeSizes []uint64,
	data *spec.AttestationData,
	started time.Time,
) ([]*spec.Attestation, error) {
	// Multisign the attestation for all validating accounts.
	signer, isSigner := accounts[0].(accountmanager.BeaconAttestationsSigner)
	if !isSigner {
		return nil, errors.New("account is not a beacon attestations signer")
	}
	uintCommitteeIndices := make([]uint64, len(committeeIndices))
	for i := range committeeIndices {
		uintCommitteeIndices[i] = uint64(committeeIndices[i])
	}
	sigs, err := signer.SignBeaconAttestations(ctx,
		duty.Slot(),
		accounts,
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

	// Submit the attestations.
	zeroSig := spec.BLSSignature{}
	attestations := make([]*spec.Attestation, len(sigs))
	_, err = util.Scatter(len(sigs), func(offset int, entries int, _ *sync.RWMutex) (interface{}, error) {
		for i := offset; i < offset+entries; i++ {
			validatorIndex, err := accounts[i].Index(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("failed to obtain validator index")
				continue
			}
			log := log.With().Uint64("slot", uint64(duty.Slot())).Uint64("validator_index", uint64(validatorIndex)).Logger()
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
			if err := s.attestationSubmitter.SubmitAttestation(ctx, attestation); err != nil {
				log.Warn().Err(err).Msg("Failed to submit attestation")
				continue
			}
			attestations[i] = attestation
			s.monitor.AttestationCompleted(started, "succeeded")
		}
		return nil, nil
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to scatter submit")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted")

	return attestations, nil
}
