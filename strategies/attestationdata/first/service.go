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

package first

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the provider for attestation data.
type Service struct {
	clientMonitor            metrics.ClientMonitor
	attestationDataProviders map[string]eth2client.AttestationDataProvider
	timeout                  time.Duration
}

// module-wide log.
var log zerolog.Logger

// New creates a new attestation data strategy.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("strategy", "attestationdata").Str("impl", "first").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		attestationDataProviders: parameters.attestationDataProviders,
		timeout:                  parameters.timeout,
		clientMonitor:            parameters.clientMonitor,
	}

	return s, nil
}

// AttestationData provides the first attestation data from a number of beacon nodes.
func (s *Service) AttestationData(ctx context.Context, slot uint64, committeeIndex uint64) (*spec.AttestationData, error) {
	// We create a cancelable context with a timeout.  As soon as the first provider has responded we
	// cancel the context to cancel the other requests.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	attestationDataCh := make(chan *spec.AttestationData, 1)
	for name, provider := range s.attestationDataProviders {
		go func(ctx context.Context, name string, provider eth2client.AttestationDataProvider, ch chan *spec.AttestationData) {
			log := log.With().Str("provider", name).Uint64("slot", slot).Logger()

			started := time.Now()
			attestationData, err := provider.AttestationData(ctx, slot, committeeIndex)
			s.clientMonitor.ClientOperation(name, "attestation data", err == nil, time.Since(started))
			if err != nil {
				log.Warn().Dur("elapsed", time.Since(started)).Err(err).Msg("Failed to obtain attestation data")
				return
			}
			if attestationData == nil {
				log.Warn().Dur("elapsed", time.Since(started)).Err(err).Msg("Returned empty attestation data")
				return
			}
			log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained attestation data")

			ch <- attestationData
		}(ctx, name, provider, attestationDataCh)
	}

	select {
	case <-ctx.Done():
		cancel()
		log.Warn().Msg("Failed to obtain attestation data before timeout")
		return nil, errors.New("failed to obtain attestation data before timeout")
	case attestationData := <-attestationDataCh:
		cancel()
		return attestationData, nil
	}
}
