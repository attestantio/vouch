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

type attestationDataResponse struct {
	attestationData *spec.AttestationData
	score           float64
}

// AttestationData provides the best attestation data from a number of beacon nodes.
func (s *Service) AttestationData(ctx context.Context, slot spec.Slot, committeeIndex spec.CommitteeIndex) (*spec.AttestationData, error) {
	started := time.Now()
	log := log.With().Uint64("slot", uint64(slot)).Logger()

	// We create a cancelable context with a timeout.  If the context times out we take the best to date.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	respCh := make(chan *attestationDataResponse, len(s.attestationDataProviders))
	errCh := make(chan error, len(s.attestationDataProviders))
	// Kick off the requests.
	for name, provider := range s.attestationDataProviders {
		go func(ctx context.Context, name string, provider eth2client.AttestationDataProvider, respCh chan *attestationDataResponse, errCh chan error) {
			attestationData, err := provider.AttestationData(ctx, slot, committeeIndex)
			s.clientMonitor.ClientOperation(name, "attestation data", err == nil, time.Since(started))
			if err != nil {
				errCh <- err
				return
			}
			log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained attestation data")
			if attestationData == nil {
				return
			}

			score := s.scoreAttestationData(ctx, provider, name, attestationData)
			respCh <- &attestationDataResponse{
				attestationData: attestationData,
				score:           score,
			}
		}(ctx, name, provider, respCh, errCh)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	bestScore := float64(0)
	var bestAttestationData *spec.AttestationData
	for responded+errored != len(s.attestationDataProviders) {
		select {
		case <-ctx.Done():
			// Anyone not responded by now is considered errored.
			errored = len(s.attestationDataProviders) - responded
			log.Debug().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Msg("Timed out waiting for responses")
		case <-errCh:
			errored++
		case resp := <-respCh:
			responded++
			if bestAttestationData == nil || resp.score > bestScore {
				bestAttestationData = resp.attestationData
				bestScore = resp.score
			}
		}
	}
	cancel()
	log.Trace().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Msg("Responses")

	if bestAttestationData == nil {
		return nil, errors.New("no attestations received")
	}
	log.Trace().Stringer("attestation_data", bestAttestationData).Float64("score", bestScore).Msg("Selected best attestation")

	return bestAttestationData, nil
}
