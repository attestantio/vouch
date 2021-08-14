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

package best

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
)

type syncCommitteeContributionResponse struct {
	provider     string
	contribution *altair.SyncCommitteeContribution
	score        float64
}

// SyncCommitteeContribution provides the sync committee contribution from a number of beacon nodes.
func (s *Service) SyncCommitteeContribution(ctx context.Context, slot phase0.Slot, subcommitteeIndex uint64, beaconBlockRoot phase0.Root) (*altair.SyncCommitteeContribution, error) {
	started := time.Now()
	log := util.LogWithID(ctx, log, "strategy_id")

	// We create a cancelable context with a timeout.  If the context times out we take the best to date.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	respCh := make(chan *syncCommitteeContributionResponse, len(s.syncCommitteeContributionProviders))
	errCh := make(chan error, len(s.syncCommitteeContributionProviders))
	// Kick off the requests.
	for name, provider := range s.syncCommitteeContributionProviders {
		go func(ctx context.Context,
			name string,
			provider eth2client.SyncCommitteeContributionProvider,
			respCh chan *syncCommitteeContributionResponse,
			errCh chan error,
		) {
			contribution, err := provider.SyncCommitteeContribution(ctx, slot, subcommitteeIndex, beaconBlockRoot)
			s.clientMonitor.ClientOperation(name, "sync committee contribution", err == nil, time.Since(started))
			if err != nil {
				errCh <- err
				return
			}
			log.Trace().Str("provider", name).Dur("elapsed", time.Since(started)).Msg("Obtained sync committee contribution")
			if contribution == nil {
				return
			}

			score := s.scoreSyncCommitteeContribution(ctx, name, contribution)
			respCh <- &syncCommitteeContributionResponse{
				provider:     name,
				contribution: contribution,
				score:        score,
			}
		}(ctx, name, provider, respCh, errCh)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	bestScore := float64(0)
	var bestSyncCommitteeContribution *altair.SyncCommitteeContribution
	bestProvider := ""

	for responded+errored != len(s.syncCommitteeContributionProviders) {
		select {
		case <-ctx.Done():
			// Anyone not responded by now is considered errored.
			errored = len(s.syncCommitteeContributionProviders) - responded
			log.Debug().Dur("elapsed", time.Since(started)).Msg("Timed out waiting for responses")
		case err := <-errCh:
			errored++
			log.Warn().Dur("elapsed", time.Since(started)).Err(err).Msg("Error")
		case resp := <-respCh:
			responded++
			if bestSyncCommitteeContribution == nil || resp.score > bestScore {
				bestSyncCommitteeContribution = resp.contribution
				bestScore = resp.score
				bestProvider = resp.provider
			}
			log.Trace().Dur("elapsed", time.Since(started)).Msg("Response")
		}
	}
	log.Trace().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Str("best_provider", bestProvider).Msg("Complete")
	cancel()

	if bestSyncCommitteeContribution == nil {
		return nil, errors.New("no sync committee contribution received")
	}
	log.Trace().Stringer("sync_committee_contribution", bestSyncCommitteeContribution).Float64("score", bestScore).Msg("Selected best sync committee contribution")
	if bestProvider != "" {
		s.clientMonitor.StrategyOperation("best", bestProvider, "sync committee contribution", time.Since(started))
	}

	return bestSyncCommitteeContribution, nil
}
