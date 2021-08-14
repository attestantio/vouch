// Copyright © 2021 Attestant Limited.
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
	"fmt"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
)

// SyncCommitteeContribution provides the sync committee contribution from a number of beacon nodes.
func (s *Service) SyncCommitteeContribution(ctx context.Context, slot phase0.Slot, subcommitteeIndex uint64, beaconBlockRoot phase0.Root) (*altair.SyncCommitteeContribution, error) {
	started := time.Now()
	log := util.LogWithID(ctx, log, "strategy_id")

	// We create a cancelable context with a timeout.  When a provider responds we cancel the context to cancel the other requests.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	respCh := make(chan *altair.SyncCommitteeContribution, 1)
	for name, provider := range s.syncCommitteeContributionProviders {
		go func(ctx context.Context,
			name string,
			provider eth2client.SyncCommitteeContributionProvider,
			ch chan *altair.SyncCommitteeContribution) {
			log := log.With().Str("provider", name).Uint64("slot", uint64(slot)).Uint64("subcommittee_index", subcommitteeIndex).Str("beacon_block_root", fmt.Sprintf("%#x", beaconBlockRoot)).Logger()

			contribution, err := provider.SyncCommitteeContribution(ctx, slot, subcommitteeIndex, beaconBlockRoot)
			s.clientMonitor.ClientOperation(name, "sync committee contribution", err == nil, time.Since(started))
			if err != nil {
				log.Warn().Dur("elapsed", time.Since(started)).Err(err).Msg("Failed to obtain sync committee contribution")
				return
			}
			if contribution == nil {
				log.Warn().Dur("elapsed", time.Since(started)).Err(err).Msg("Returned empty sync committee contribution")
				return
			}
			log.Trace().Str("provider", name).Dur("elapsed", time.Since(started)).Msg("Obtained sync committee contribution")

			ch <- contribution
		}(ctx, name, provider, respCh)
	}

	select {
	case <-ctx.Done():
		cancel()
		log.Warn().Msg("Failed to obtain sync committee contribution before timeout")
		return nil, errors.New("failed to obtain sync committee contribution before timeout")
	case aggregate := <-respCh:
		cancel()
		return aggregate, nil
	}
}
