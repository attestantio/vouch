// Copyright © 2021, 2022 Attestant Limited.
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

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)

	respCh := make(chan *syncCommitteeContributionResponse, len(s.syncCommitteeContributionProviders))
	errCh := make(chan error, len(s.syncCommitteeContributionProviders))
	// Kick off the requests.
	for name, provider := range s.syncCommitteeContributionProviders {
		go s.syncCommitteeContribution(ctx, started, name, provider, respCh, errCh, slot, subcommitteeIndex, beaconBlockRoot)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	timedOut := 0
	bestScore := float64(0)
	var bestSyncCommitteeContribution *altair.SyncCommitteeContribution
	bestProvider := ""

	for responded+errored+timedOut != len(s.syncCommitteeContributionProviders) {
		select {
		case <-softCtx.Done():
			// If we have any responses at this point we consider the non-responders timed out.
			if responded > 0 {
				timedOut = len(s.syncCommitteeContributionProviders) - responded - errored
				log.Debug().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Msg("Soft timeout reached with responses")
			} else {
				log.Debug().Dur("elapsed", time.Since(started)).Int("errored", errored).Msg("Soft timeout reached with no responses")
			}
		case <-ctx.Done():
			// Anyone not responded by now is considered errored.
			errored = len(s.syncCommitteeContributionProviders) - responded
			log.Debug().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Hard timeout reached")
		case err := <-errCh:
			errored++
			log.Debug().Dur("elapsed", time.Since(started)).Err(err).Msg("Responded with error")
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
	softCancel()
	cancel()
	log.Trace().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Responses")

	if bestSyncCommitteeContribution == nil {
		return nil, errors.New("no sync committee contribution received")
	}
	log.Trace().Str("provider", bestProvider).Stringer("sync_committee_contribution", bestSyncCommitteeContribution).Float64("score", bestScore).Msg("Selected best sync committee contribution")
	if bestProvider != "" {
		s.clientMonitor.StrategyOperation("best", bestProvider, "sync committee contribution", time.Since(started))
	}

	return bestSyncCommitteeContribution, nil
}

func (s *Service) syncCommitteeContribution(ctx context.Context,
	started time.Time,
	name string,
	provider eth2client.SyncCommitteeContributionProvider,
	respCh chan *syncCommitteeContributionResponse,
	errCh chan error,
	slot phase0.Slot,
	subcommitteeIndex uint64,
	beaconBlockRoot phase0.Root,
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
}
