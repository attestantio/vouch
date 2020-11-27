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

package multinode

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"golang.org/x/sync/semaphore"
)

// SubmitAttestations submits a batch of attestations.
func (s *Service) SubmitAttestations(ctx context.Context, attestations []*spec.Attestation) error {
	if len(attestations) == 0 {
		return errors.New("no attestations supplied")
	}

	sem := semaphore.NewWeighted(s.processConcurrency)
	var wg sync.WaitGroup
	for name, submitter := range s.attestationsSubmitters {
		wg.Add(1)
		go func(ctx context.Context,
			sem *semaphore.Weighted,
			wg *sync.WaitGroup,
			name string,
			submitter eth2client.AttestationsSubmitter,
		) {
			defer wg.Done()
			log := log.With().Str("beacon_node_address", name).Uint64("slot", uint64(attestations[0].Data.Slot)).Logger()
			if err := sem.Acquire(ctx, 1); err != nil {
				log.Error().Err(err).Msg("Failed to acquire semaphore")
				return
			}
			defer sem.Release(1)

			serverType, address := s.serviceInfo(ctx, submitter)
			started := time.Now()
			err := submitter.SubmitAttestations(ctx, attestations)
			s.clientMonitor.ClientOperation(address, "submit attestations", err == nil, time.Since(started))
			if err != nil {
				switch {
				case serverType == "lighthouse" && strings.Contains(err.Error(), "PriorAttestationKnown"):
					// Lighthouse rejects duplicate attestations.  It is possible that an attestation we sent
					// to another node already propagated to this node, so ignore the error.
					log.Trace().Msg("Node already knows about attestation; ignored")
				case serverType == "lighthouse" && strings.Contains(err.Error(), "UnknownHeadBlock"):
					// Lighthouse rejects an attestation for a block  that is not its current head.  It is possible
					// that the node is just behind, and we can't do anything about it anyway at this point having
					// already signed an attestation for this slot, so ignore the error.
					log.Debug().Err(err).Msg("Node does not know head block; rejected")
				case serverType == "lighthouse" && strings.Contains(err.Error(), "InvalidSignature"):
					data, err2 := json.Marshal(attestations)
					if err2 != nil {
						log.Error().Err(err).Msg("Failed to marshal JSON")
					} else {
						log.Warn().Err(err).Str("data", string(data)).Msg("Invalid signature!")
					}
				default:
					log.Warn().Err(err).Msg("Failed to submit attestation")
				}
			} else {
				data, err := json.Marshal(attestations)
				if err != nil {
					log.Error().Err(err).Msg("Failed to marshal JSON")
				} else {
					log.Trace().Str("data", string(data)).Msg("Submitted attestations")
				}
			}
		}(ctx, sem, &wg, name, submitter)
	}
	wg.Wait()

	return nil
}
