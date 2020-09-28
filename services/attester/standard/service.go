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
	"fmt"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
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
	log := log.With().Uint64("slot", duty.Slot()).Logger()
	log.Trace().Uints64("validator_indices", duty.ValidatorIndices()).Msg("Attesting")

	attestations := make([]*spec.Attestation, 0, len(duty.ValidatorIndices()))
	var attestationsMutex sync.Mutex

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

	// Fetch the validating accounts.
	accounts, err := s.validatingAccountsProvider.AccountsByIndex(ctx, duty.ValidatorIndices())
	if err != nil {
		s.monitor.AttestationCompleted(started, "failed")
		return nil, errors.New("failed to obtain attesting validator accounts")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Uints64("validator_indices", duty.ValidatorIndices()).Msg("Obtained validating accounts")

	// Run the attestations in parallel, up to a concurrency limit.
	validatorIndexToArrayIndexMap := make(map[uint64]int)
	for i := range duty.ValidatorIndices() {
		validatorIndexToArrayIndexMap[duty.ValidatorIndices()[i]] = i
	}
	sem := semaphore.NewWeighted(s.processConcurrency)
	var wg sync.WaitGroup
	for _, account := range accounts {
		wg.Add(1)
		go func(sem *semaphore.Weighted, wg *sync.WaitGroup, account accountmanager.ValidatingAccount, attestations *[]*spec.Attestation, attestationsMutex *sync.Mutex) {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				log.Error().Err(err).Msg("Failed to acquire semaphore")
				return
			}
			defer sem.Release(1)

			validatorIndex, err := account.Index(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to obtain validator index")
				return
			}
			log := log.With().Uint64("validator_index", validatorIndex).Logger()
			attestation, err := s.attest(ctx,
				duty.Slot(),
				duty.CommitteeIndices()[validatorIndexToArrayIndexMap[validatorIndex]],
				duty.ValidatorCommitteeIndices()[validatorIndexToArrayIndexMap[validatorIndex]],
				duty.CommitteeSize(duty.CommitteeIndices()[validatorIndexToArrayIndexMap[validatorIndex]]),
				account,
				attestationData,
			)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to attest")
				s.monitor.AttestationCompleted(started, "failed")
				return
			}
			log.Trace().Dur("elapsed", time.Since(started)).Msg("Attested")
			s.monitor.AttestationCompleted(started, "succeeded")
			attestationsMutex.Lock()
			*attestations = append(*attestations, attestation)
			attestationsMutex.Unlock()

		}(sem, &wg, account, &attestations, &attestationsMutex)
	}
	wg.Wait()

	return attestations, nil
}

func (s *Service) attest(
	ctx context.Context,
	slot uint64,
	committeeIndex uint64,
	validatorCommitteeIndex uint64,
	committeeSize uint64,
	account accountmanager.ValidatingAccount,
	attestationData *spec.AttestationData,
) (*spec.Attestation, error) {

	// Sign the attestation.
	signer, isSigner := account.(accountmanager.BeaconAttestationSigner)
	if !isSigner {
		return nil, errors.New("account is not a beacon attestation signer")
	}
	sig, err := signer.SignBeaconAttestation(ctx,
		slot,
		committeeIndex,
		attestationData.BeaconBlockRoot,
		attestationData.Source.Epoch,
		attestationData.Source.Root,
		attestationData.Target.Epoch,
		attestationData.Target.Root)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign beacon attestation")
	}
	log.Trace().Msg("Signed")

	// Submit the attestation.
	aggregationBits := bitfield.NewBitlist(committeeSize)
	aggregationBits.SetBitAt(validatorCommitteeIndex, true)
	attestation := &spec.Attestation{
		AggregationBits: aggregationBits,
		Data: &spec.AttestationData{
			Slot:            slot,
			Index:           committeeIndex,
			BeaconBlockRoot: attestationData.BeaconBlockRoot,
			Source: &spec.Checkpoint{
				Epoch: attestationData.Source.Epoch,
				Root:  attestationData.Source.Root,
			},
			Target: &spec.Checkpoint{
				Epoch: attestationData.Target.Epoch,
				Root:  attestationData.Target.Root,
			},
		},
		Signature: sig,
	}
	if err := s.attestationSubmitter.SubmitAttestation(ctx, attestation); err != nil {
		return nil, errors.Wrap(err, "failed to submit attestation")
	}
	return attestation, nil
}
