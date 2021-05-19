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

package best

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

type aggregateAttestationResponse struct {
	provider  string
	aggregate *spec.Attestation
	score     float64
}

// AggregateAttestation provides the aggregate attestation from a number of beacon nodes.
func (s *Service) AggregateAttestation(ctx context.Context, slot spec.Slot, attestationDataRoot spec.Root) (*spec.Attestation, error) {
	started := time.Now()

	// We create a cancelable context with a timeout.  If the context times out we take the best to date.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	respCh := make(chan *aggregateAttestationResponse, len(s.aggregateAttestationProviders))
	errCh := make(chan error, len(s.aggregateAttestationProviders))
	// Kick off the requests.
	for name, provider := range s.aggregateAttestationProviders {
		go func(ctx context.Context,
			name string,
			provider eth2client.AggregateAttestationProvider,
			respCh chan *aggregateAttestationResponse,
			errCh chan error,
		) {
			aggregate, err := provider.AggregateAttestation(ctx, slot, attestationDataRoot)
			s.clientMonitor.ClientOperation(name, "aggregate attestation", err == nil, time.Since(started))
			if err != nil {
				errCh <- err
				return
			}
			log.Trace().Str("provider", name).Dur("elapsed", time.Since(started)).Msg("Obtained aggregate attestation")
			if aggregate == nil {
				return
			}

			score := s.scoreAggregateAttestation(ctx, name, aggregate)
			respCh <- &aggregateAttestationResponse{
				provider:  name,
				aggregate: aggregate,
				score:     score,
			}
		}(ctx, name, provider, respCh, errCh)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	bestScore := float64(0)
	var bestAggregateAttestation *spec.Attestation
	bestProvider := ""

	for responded+errored != len(s.aggregateAttestationProviders) {
		select {
		case <-ctx.Done():
			// Anyone not responded by now is considered errored.
			errored = len(s.aggregateAttestationProviders) - responded
			log.Info().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Msg("Timed out waiting for responses")
		case <-errCh:
			errored++
		case resp := <-respCh:
			responded++
			if bestAggregateAttestation == nil || resp.score > bestScore {
				bestAggregateAttestation = resp.aggregate
				bestScore = resp.score
				bestProvider = resp.provider
			}
		}
	}
	cancel()

	if bestAggregateAttestation == nil {
		return nil, errors.New("no aggregate attestations received")
	}
	log.Trace().Stringer("aggregate_attestation", bestAggregateAttestation).Float64("score", bestScore).Msg("Selected best aggregate attestation")
	if bestProvider != "" {
		s.clientMonitor.StrategyOperation("best", bestProvider, "aggregate attestation", time.Since(started))
	}

	return bestAggregateAttestation, nil
}
