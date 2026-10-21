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
	"fmt"
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
	proposerDelay              time.Duration
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
	// Read the fork epoch from the same snapshot as the deadlines.  A missing or malformed value
	// means no Gloas fork, as in chaintime.HardForkEpoch.
	gloasForkEpoch := chaintime.FarFutureEpoch
	if epoch, ok := specResponse.Data["GLOAS_FORK_EPOCH"].(uint64); ok {
		gloasForkEpoch = phase0.Epoch(epoch)
	}
	preGloasAttestationDelay, gloasAttestationDelay, slotDuration, err := obtainAttestationDelays(specResponse.Data, gloasForkEpoch)
	if err != nil {
		return nil, err
	}
	// The controller applies its override to pre-Gloas slots only.
	if parameters.maxAttestationDelay != 0 {
		preGloasAttestationDelay = parameters.maxAttestationDelay
	}
	// A pool check at or after the end of the slot is too late to take over.  Only check slots
	// that can still occur.
	if parameters.chainTime.CurrentEpoch() < gloasForkEpoch && preGloasAttestationDelay+parameters.attesterDelay >= slotDuration {
		until := ""
		if gloasForkEpoch != chaintime.FarFutureEpoch {
			until = fmt.Sprintf(" until Gloas activates at epoch %d", gloasForkEpoch)
		}

		return nil, errors.Errorf("pre-Gloas attestation deadline %s plus multiinstance.static-delay.attester-delay %s must be less than the slot duration %s%s", preGloasAttestationDelay, parameters.attesterDelay, slotDuration, until)
	}
	if gloasForkEpoch != chaintime.FarFutureEpoch && gloasAttestationDelay+parameters.attesterDelay >= slotDuration {
		return nil, errors.Errorf("Gloas attestation deadline %s plus multiinstance.static-delay.attester-delay %s must be less than the slot duration %s", gloasAttestationDelay, parameters.attesterDelay, slotDuration)
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
	monitorActive("attester", parameters.attesterDelay == 0)
	monitorActive("proposer", parameters.proposerDelay == 0)
	log.Info().Bool("attester_active", parameters.attesterDelay == 0).Bool("proposer_active", parameters.proposerDelay == 0).Msg("Initial configuration")

	return s, nil
}

// obtainAttestationDelays provides the pre-Gloas and Gloas attestation deadlines, and the slot duration.
func obtainAttestationDelays(spec map[string]any, gloasForkEpoch phase0.Epoch) (
	time.Duration,
	time.Duration,
	time.Duration,
	error,
) {
	tmp, exists := spec["SECONDS_PER_SLOT"]
	if !exists {
		return 0, 0, 0, errors.New("failed to obtain SECONDS_PER_SLOT")
	}
	secondsPerSlot, isDuration := tmp.(time.Duration)
	if !isDuration {
		return 0, 0, 0, errors.New("seconds per slot not a duration")
	}

	// Match the controller's default pre-Gloas attestation deadline.
	preGloasDelay := secondsPerSlot / 3

	// Chaintime times every slot from SECONDS_PER_SLOT, including after Gloas, so the Gloas deadline
	// is a fraction of it and a scheduled fork must not change the slot duration.
	if gloasSlotDuration := chaintime.GloasSlotDuration(spec, secondsPerSlot); gloasForkEpoch != chaintime.FarFutureEpoch && gloasSlotDuration != secondsPerSlot {
		return 0, 0, 0, errors.Errorf("SLOT_DURATION_MS %s differs from SECONDS_PER_SLOT %s; chaintime does not support changing slot duration", gloasSlotDuration, secondsPerSlot)
	}
	// The fallback is ATTESTATION_DUE_BPS_GLOAS itself, 2500 basis points.
	gloasDelay := chaintime.DueBPS(spec, "ATTESTATION_DUE_BPS_GLOAS", secondsPerSlot, secondsPerSlot/4)

	return preGloasDelay, gloasDelay, secondsPerSlot, nil
}
