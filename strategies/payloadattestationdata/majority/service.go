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

package majority

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
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
	threshold                       int
}

// New creates a payload attestation data strategy.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}
	log := zerologger.With().Str("strategy", "payloadattestationdata").Str("impl", "majority").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}
	return &Service{
		log:                             log,
		clientMonitor:                   parameters.clientMonitor,
		payloadAttestationDataProviders: parameters.payloadAttestationDataProviders,
		timeout:                         parameters.timeout,
		threshold:                       parameters.threshold,
	}, nil
}

type payloadAttestationDataKey struct {
	version           spec.DataVersion
	beaconBlockRoot   phase0.Root
	slot              phase0.Slot
	payloadPresent    bool
	blobDataAvailable bool
}

type payloadAttestationDataResult struct {
	provider string
	response *api.Response[*spec.VersionedPayloadAttestationData]
	err      error
}

// PayloadAttestationData obtains the strongest valid agreement for payload attestation data.
func (s *Service) PayloadAttestationData(ctx context.Context, opts *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	started := time.Now()
	results := make(chan payloadAttestationDataResult, len(s.payloadAttestationDataProviders))
	for name, provider := range s.payloadAttestationDataProviders {
		go func() {
			response, err := provider.PayloadAttestationData(ctx, opts)
			s.clientMonitor.ClientOperation(name, "payload attestation data", err == nil, time.Since(started))
			results <- payloadAttestationDataResult{provider: name, response: response, err: err}
		}()
	}

	buckets := make(map[payloadAttestationDataKey][]payloadAttestationDataResult)
	requests := len(s.payloadAttestationDataProviders)
	strictMajority := requests/2 + 1
	requiredCount := max(strictMajority, s.threshold)
	largestCount := 0
	completed := 0
	for completed < requests && largestCount < requiredCount {
		select {
		case <-ctx.Done():
			completed = requests
		case result := <-results:
			completed++
			if result.err != nil {
				s.log.Debug().Err(result.err).Str("provider", result.provider).Msg("Failed to obtain payload attestation data")
				continue
			}
			if result.response == nil || result.response.Data == nil || result.response.Data.Version != spec.DataVersionGloas || result.response.Data.Gloas == nil || result.response.Data.Gloas.Slot != opts.Slot {
				s.log.Debug().Str("provider", result.provider).Msg("Received invalid payload attestation data")
				continue
			}
			key := payloadAttestationDataKey{
				version:           result.response.Data.Version,
				beaconBlockRoot:   result.response.Data.Gloas.BeaconBlockRoot,
				slot:              result.response.Data.Gloas.Slot,
				payloadPresent:    result.response.Data.Gloas.PayloadPresent,
				blobDataAvailable: result.response.Data.Gloas.BlobDataAvailable,
			}
			buckets[key] = append(buckets[key], result)
			if len(buckets[key]) > largestCount {
				largestCount = len(buckets[key])
			}
		}
	}

	if ctx.Err() != nil {
		return nil, errors.Wrap(ctx.Err(), "failed to obtain payload attestation data")
	}
	if len(buckets) == 0 {
		return nil, errors.New("no valid payload attestation data received")
	}

	leading := make([]payloadAttestationDataKey, 0, 2)
	for key, responses := range buckets {
		switch {
		case len(responses) > largestCount:
			largestCount = len(responses)
			leading = append(leading[:0], key)
		case len(responses) == largestCount:
			leading = append(leading, key)
		}
	}
	if largestCount < s.threshold {
		s.log.Debug().Int("count", largestCount).Int("threshold", s.threshold).Msg("Insufficient payload attestation data agreement")
		return nil, errors.Errorf("payload attestation data count of %d lower than threshold %d", largestCount, s.threshold)
	}
	if len(leading) == 1 {
		return s.selectedPayloadAttestationData(started, buckets[leading[0]]), nil
	}

	first := leading[0]
	for _, key := range leading[1:] {
		if key.version != first.version || key.slot != first.slot || key.beaconBlockRoot != first.beaconBlockRoot {
			s.log.Debug().Msg("Split payload attestation data roots")
			return nil, errors.New("split-root payload attestation data responses")
		}
	}

	var selected *payloadAttestationDataKey
	for i := range leading {
		if leading[i].payloadPresent {
			if selected != nil {
				s.log.Debug().Msg("Split payload attestation data responses")
				return nil, errors.New("split-response payload attestation data responses")
			}
			selected = &leading[i]
		}
	}
	if selected == nil {
		s.log.Debug().Msg("Split payload attestation data responses")
		return nil, errors.New("split-response payload attestation data responses")
	}
	s.log.Debug().Msg("Resolved payload attestation data tie with payload present")
	return s.selectedPayloadAttestationData(started, buckets[*selected]), nil
}

func (s *Service) selectedPayloadAttestationData(started time.Time, responses []payloadAttestationDataResult) *api.Response[*spec.VersionedPayloadAttestationData] {
	for _, response := range responses {
		s.clientMonitor.StrategyOperation("majority", response.provider, "payload attestation data", time.Since(started))
	}
	return &api.Response[*spec.VersionedPayloadAttestationData]{
		Data:     responses[0].response.Data,
		Metadata: make(map[string]any),
	}
}
