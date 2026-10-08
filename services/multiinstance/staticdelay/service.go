// Copyright © 2024 - 2026 Attestant Limited.
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

// Package staticdelay provides a static delay in which a Vouch instance waits
// to see if another instance has attested or proposed before doing so itself.
package staticdelay

import (
	"context"
	"sync/atomic"
	"time"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the multi instance service.
type Service struct {
	log                        zerolog.Logger
	monitor                    metrics.Service
	attestationPoolProvider    consensusclient.AttestationPoolProvider
	beaconBlockHeadersProvider consensusclient.BeaconBlockHeadersProvider
	chainTime                  chaintime.Service
	preGloasAttestationDelay   time.Duration
	gloasAttestationDelay      time.Duration
	gloasForkEpoch             phase0.Epoch
	attesterDelay              time.Duration
	attesterActive             atomic.Bool
	proposerDelay              time.Duration
	proposerActive             atomic.Bool
}

// New creates a new controller.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "multiinstance").Str("impl", "staticdelay").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}

	specResponse, err := parameters.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, err
	}
	preGloasAttestationDelay, gloasAttestationDelay, gloasForkEpoch, err := obtainAttestationDelays(specResponse.Data)
	if err != nil {
		return nil, err
	}
	log.Trace().Dur("pre_gloas_delay", preGloasAttestationDelay).Dur("gloas_delay", gloasAttestationDelay).Msg("Obtained spec attestation delays")

	s := &Service{
		log:                        log,
		monitor:                    parameters.monitor,
		attestationPoolProvider:    parameters.attestationPoolProvider,
		beaconBlockHeadersProvider: parameters.beaconBlockHeadersProvider,
		chainTime:                  parameters.chainTime,
		preGloasAttestationDelay:   preGloasAttestationDelay,
		gloasAttestationDelay:      gloasAttestationDelay,
		gloasForkEpoch:             gloasForkEpoch,
		attesterDelay:              parameters.attesterDelay,
		proposerDelay:              parameters.proposerDelay,
	}
	s.attesterActive.Store(parameters.attesterDelay == 0)
	monitorActive("attester", parameters.attesterDelay == 0)
	s.proposerActive.Store(parameters.proposerDelay == 0)
	monitorActive("proposer", parameters.proposerDelay == 0)
	log.Info().Bool("attester_active", parameters.attesterDelay == 0).Bool("proposer_active", parameters.proposerDelay == 0).Msg("Initial configuration")

	return s, nil
}

func (s *Service) disableAttester(_ context.Context) {
	s.attesterActive.Store(false)
	monitorActive("attester", false)
	// We also deactivate the proposer pre-emptively, on the basis that if we cannot attest we are unlikely to be able to propose.
	s.proposerActive.Store(false)
}

func (s *Service) enableAttester(_ context.Context) {
	s.attesterActive.Store(true)
	monitorActive("attester", true)
	// We also activate the proposer pre-emptively, on the basis that if we are attesting we should be proposing also.
	s.proposerActive.Store(true)
}

func (s *Service) disableProposer(_ context.Context) {
	s.proposerActive.Store(false)
	monitorActive("proposer", false)
}

func (s *Service) enableProposer(_ context.Context) {
	s.proposerActive.Store(true)
	monitorActive("proposer", true)
}

// obtainAttestationDelays provides both attestation deadlines and their Gloas fork epoch.
func obtainAttestationDelays(spec map[string]any) (
	time.Duration,
	time.Duration,
	phase0.Epoch,
	error,
) {
	gloasForkEpoch := phase0.Epoch(^uint64(0))
	if raw, exists := spec["GLOAS_FORK_EPOCH"]; exists {
		epoch, ok := raw.(uint64)
		if !ok {
			return 0, 0, 0, errors.New("GLOAS_FORK_EPOCH is not a uint64")
		}
		gloasForkEpoch = phase0.Epoch(epoch)
	}

	tmp, exists := spec["SECONDS_PER_SLOT"]
	if !exists {
		return 0, 0, 0, errors.New("failed to obtain SECONDS_PER_SLOT")
	}
	secondsPerSlot, isDuration := tmp.(time.Duration)
	if !isDuration {
		return 0, 0, 0, errors.New("seconds per slot not a duration")
	}

	// Match the controller's pre-Gloas attestation deadline.
	delay := secondsPerSlot / 3

	// Chaintime uses SECONDS_PER_SLOT for slot starts, including after Gloas.
	gloasSlotDuration := secondsPerSlot
	if durationMS, ok := spec["SLOT_DURATION_MS"].(uint64); ok && durationMS != 0 {
		gloasSlotDuration = time.Duration(durationMS) * time.Millisecond
		if gloasForkEpoch != phase0.Epoch(^uint64(0)) && gloasSlotDuration != secondsPerSlot {
			return 0, 0, 0, errors.New("SLOT_DURATION_MS differs from SECONDS_PER_SLOT; chaintime does not support changing slot duration")
		}
	}
	// The fallback is ATTESTATION_DUE_BPS_GLOAS itself, 2500 basis points.
	gloasDelay := gloasSlotDuration / 4
	if bps, ok := spec["ATTESTATION_DUE_BPS_GLOAS"].(uint64); ok && bps != 0 && bps <= 10000 {
		gloasDelay = gloasSlotDuration * time.Duration(bps) / 10000
	}

	return delay, gloasDelay, gloasForkEpoch, nil
}
