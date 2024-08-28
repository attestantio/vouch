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
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/altair"
	clientprometheus "github.com/attestantio/vouch/services/metrics/prometheus"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type syncCommitteeContributionResponse struct {
	provider     string
	contribution *altair.SyncCommitteeContribution
	score        float64
}

type syncCommitteeContributionError struct {
	provider string
	err      error
}

// SyncCommitteeContribution provides the sync committee contribution from a number of beacon nodes.
func (s *Service) SyncCommitteeContribution(ctx context.Context,
	opts *api.SyncCommitteeContributionOpts,
) (
	*api.Response[*altair.SyncCommitteeContribution],
	error,
) {
	if opts == nil {
		return nil, errors.New("no options specified")
	}

	ctx, span := otel.Tracer("attestantio.vouch.strategies.synccommitteecontribution.best").Start(ctx, "SyncCommitteeContribution", trace.WithAttributes(
		attribute.Int64("slot", util.SlotToInt64(opts.Slot)),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, s.log, "strategy_id")

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)

	requests := len(s.syncCommitteeContributionProviders)

	respCh := make(chan *syncCommitteeContributionResponse, requests)
	errCh := make(chan *syncCommitteeContributionError, requests)
	// Kick off the requests.
	for name, provider := range s.syncCommitteeContributionProviders {
		go s.syncCommitteeContribution(ctx, started, name, provider, respCh, errCh, opts)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	timedOut := 0
	softTimedOut := 0
	bestScore := float64(0)
	var bestSyncCommitteeContribution *altair.SyncCommitteeContribution
	var bestProvider string

	// Loop 1: prior to soft timeout.
	for responded+errored+timedOut+softTimedOut != requests {
		select {
		case resp := <-respCh:
			responded++
			log.Trace().
				Dur("elapsed", time.Since(started)).
				Str("provider", resp.provider).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", timedOut).
				Msg("Response received")
			if bestSyncCommitteeContribution == nil || resp.score > bestScore {
				bestSyncCommitteeContribution = resp.contribution
				bestScore = resp.score
				bestProvider = resp.provider
			}
		case err := <-errCh:
			errored++
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Str("provider", err.provider).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", timedOut).
				Err(err.err).
				Msg("Error received")
		case <-softCtx.Done():
			// If we have any responses at this point we consider the non-responders timed out.
			if responded > 0 {
				timedOut = requests - responded - errored
				log.Debug().
					Dur("elapsed", time.Since(started)).
					Int("responded", responded).
					Int("errored", errored).
					Int("timed_out", timedOut).
					Msg("Soft timeout reached with responses")
			} else {
				log.Debug().
					Dur("elapsed", time.Since(started)).
					Int("errored", errored).
					Msg("Soft timeout reached with no responses")
			}
			// Set the number of requests that have soft timed out.
			softTimedOut = requests - responded - errored - timedOut
		}
	}
	softCancel()

	// Loop 2: after soft timeout.
	for responded+errored+timedOut != requests {
		select {
		case resp := <-respCh:
			responded++
			log.Trace().
				Dur("elapsed", time.Since(started)).
				Str("provider", resp.provider).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", timedOut).
				Msg("Response received")
			if bestSyncCommitteeContribution == nil || resp.score > bestScore {
				bestSyncCommitteeContribution = resp.contribution
				bestScore = resp.score
				bestProvider = resp.provider
			}
		case err := <-errCh:
			errored++
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Str("provider", err.provider).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", timedOut).
				Err(err.err).
				Msg("Error received")
		case <-ctx.Done():
			// Anyone not responded by now is considered errored.
			timedOut = requests - responded - errored
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", timedOut).
				Msg("Hard timeout reached")
		}
	}
	cancel()
	log.Trace().
		Dur("elapsed", time.Since(started)).
		Int("responded", responded).
		Int("errored", errored).
		Int("timed_out", timedOut).
		Msg("Results")

	if bestSyncCommitteeContribution == nil {
		return nil, errors.New("no sync committee contribution received")
	}
	log.Trace().Str("provider", bestProvider).Stringer("sync_committee_contribution", bestSyncCommitteeContribution).Float64("score", bestScore).Msg("Selected best sync committee contribution")
	if bestProvider != "" {
		clientprometheus.MonitorStrategyOperation("best", bestProvider, "sync committee contribution", time.Since(started))
	}

	return &api.Response[*altair.SyncCommitteeContribution]{
		Data:     bestSyncCommitteeContribution,
		Metadata: make(map[string]any),
	}, nil
}

func (s *Service) syncCommitteeContribution(ctx context.Context,
	started time.Time,
	name string,
	provider eth2client.SyncCommitteeContributionProvider,
	respCh chan *syncCommitteeContributionResponse,
	errCh chan *syncCommitteeContributionError,
	opts *api.SyncCommitteeContributionOpts,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.synccommitteecontribution.best").Start(ctx, "syncCommitteeContribution", trace.WithAttributes(
		attribute.String("provider", name),
	))
	defer span.End()

	contributionResponse, err := provider.SyncCommitteeContribution(ctx, opts)
	clientprometheus.MonitorClientOperation(name, "sync committee contribution", err == nil, time.Since(started))
	if err != nil {
		errCh <- &syncCommitteeContributionError{
			provider: name,
			err:      err,
		}
		return
	}
	contribution := contributionResponse.Data
	s.log.Trace().Str("provider", name).Dur("elapsed", time.Since(started)).Msg("Obtained sync committee contribution")
	if contribution == nil {
		errCh <- &syncCommitteeContributionError{
			provider: name,
			err:      errors.New("sync committee contribution nil"),
		}
		return
	}

	score := s.scoreSyncCommitteeContribution(ctx, name, contribution)
	respCh <- &syncCommitteeContributionResponse{
		provider:     name,
		contribution: contribution,
		score:        score,
	}
}
