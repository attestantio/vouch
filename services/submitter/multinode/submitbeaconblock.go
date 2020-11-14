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
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"golang.org/x/sync/semaphore"
)

// SubmitBeaconBlock submits a beacon block.
func (s *Service) SubmitBeaconBlock(ctx context.Context, block *spec.SignedBeaconBlock) error {
	if block == nil {
		return errors.New("no beacon block supplied")
	}

	sem := semaphore.NewWeighted(s.processConcurrency)
	var wg sync.WaitGroup
	for name, submitter := range s.beaconBlockSubmitters {
		wg.Add(1)
		go func(ctx context.Context,
			sem *semaphore.Weighted,
			wg *sync.WaitGroup,
			name string,
			submitter eth2client.BeaconBlockSubmitter,
		) {
			defer wg.Done()
			log := log.With().Str("beacon_node_address", name).Uint64("slot", uint64(block.Message.Slot)).Logger()
			if err := sem.Acquire(ctx, 1); err != nil {
				log.Error().Err(err).Msg("Failed to acquire semaphore")
				return
			}
			defer sem.Release(1)

			started := time.Now()
			err := submitter.SubmitBeaconBlock(ctx, block)
			if service, isService := submitter.(eth2client.Service); isService {
				s.clientMonitor.ClientOperation(service.Address(), "submit beacon block", err == nil, time.Since(started))
			} else {
				s.clientMonitor.ClientOperation("<unknown>", "submit beacon block", err == nil, time.Since(started))
			}
			if err != nil {
				log.Warn().Err(err).Msg("Failed to submit beacon block")
				return
			}
			log.Trace().Msg("Submitted beacon block")
		}(ctx, sem, &wg, name, submitter)
	}
	wg.Wait()

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(block)
		if err == nil {
			e.Str("block", string(data)).Msg("Submitted beacon block")
		}
	}

	return nil
}
