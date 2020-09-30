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

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"golang.org/x/sync/semaphore"
)

// SubmitAttestation submits an attestation.
func (s *Service) SubmitAttestation(ctx context.Context, attestation *spec.Attestation) error {
	if attestation == nil {
		return errors.New("no attestation supplied")
	}

	sem := semaphore.NewWeighted(s.processConcurrency)
	var wg sync.WaitGroup
	for name, submitter := range s.attestationSubmitters {
		wg.Add(1)
		go func(ctx context.Context,
			sem *semaphore.Weighted,
			wg *sync.WaitGroup,
			name string,
			submitter eth2client.AttestationSubmitter,
		) {
			defer wg.Done()
			log := log.With().Str("beacon_node_address", name).Uint64("slot", attestation.Data.Slot).Logger()
			if err := sem.Acquire(ctx, 1); err != nil {
				log.Error().Err(err).Msg("Failed to acquire semaphore")
				return
			}
			defer sem.Release(1)

			if err := submitter.SubmitAttestation(ctx, attestation); err != nil {
				if strings.Contains(err.Error(), "PriorAttestationKnown") {
					// Lighthouse rejects duplicate attestations.  It is possible that an attestation we sent
					// to another node already propagated to this node, so ignore the error.
					log.Trace().Msg("Node already knows about attestation; ignored")
				} else {
					log.Warn().Err(err).Msg("Failed to submit attestation")
				}
				return
			}
			log.Trace().Msg("Submitted attestation")
		}(ctx, sem, &wg, name, submitter)
	}
	wg.Wait()

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(attestation)
		if err == nil {
			e.Str("attestation", string(data)).Msg("Submitted attestation")
		}
	}

	return nil
}
