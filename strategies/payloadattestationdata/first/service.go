// Copyright © 2026 Attestant Limited.
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
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service provides payload attestation data.
type Service struct {
	log                             zerolog.Logger
	clientMonitor                   metrics.ClientMonitor
	payloadAttestationDataProviders map[string]eth2client.PayloadAttestationDataProvider
	timeout                         time.Duration
}

// New creates a payload attestation data strategy.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}
	log := zerologger.With().Str("strategy", "payloadattestationdata").Str("impl", "first").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}
	return &Service{
		log:                             log,
		clientMonitor:                   parameters.clientMonitor,
		payloadAttestationDataProviders: parameters.payloadAttestationDataProviders,
		timeout:                         parameters.timeout,
	}, nil
}

// PayloadAttestationData obtains the first valid payload attestation data response.
func (s *Service) PayloadAttestationData(ctx context.Context, opts *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	started := time.Now()
	type result struct {
		provider string
		response *api.Response[*spec.VersionedPayloadAttestationData]
		err      error
	}
	results := make(chan result, len(s.payloadAttestationDataProviders))
	for name, provider := range s.payloadAttestationDataProviders {
		go func(providerName string, provider eth2client.PayloadAttestationDataProvider) {
			response, err := provider.PayloadAttestationData(ctx, opts)
			s.clientMonitor.ClientOperation(providerName, "payload attestation data", err == nil, time.Since(started))
			results <- result{provider: providerName, response: response, err: err}
		}(name, provider)
	}

	for range s.payloadAttestationDataProviders {
		select {
		case <-ctx.Done():
			return nil, errors.Wrap(ctx.Err(), "failed to obtain payload attestation data")
		case result := <-results:
			if result.err != nil {
				s.log.Debug().Err(result.err).Str("provider", result.provider).Msg("Failed to obtain payload attestation data")
				continue
			}
			if result.response == nil || result.response.Data == nil || result.response.Data.Version != spec.DataVersionGloas || result.response.Data.Gloas == nil || result.response.Data.Gloas.Slot != opts.Slot {
				s.log.Debug().Str("provider", result.provider).Msg("Received invalid payload attestation data")
				continue
			}
			s.clientMonitor.StrategyOperation("first", result.provider, "payload attestation data", time.Since(started))
			return &api.Response[*spec.VersionedPayloadAttestationData]{
				Data:     result.response.Data,
				Metadata: make(map[string]any),
			}, nil
		}
	}

	return nil, errors.New("no valid payload attestation data received")
}
