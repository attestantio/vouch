// Copyright © 2023 Attestant Limited.
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
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	clientprometheus "github.com/attestantio/vouch/services/metrics/prometheus"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type beaconBlockRootResponse struct {
	provider string
	root     *phase0.Root
}

type beaconBlockRootError struct {
	provider string
	err      error
}

// BeaconBlockRoot provides the consensus root from a number of beacon nodes.
func (s *Service) BeaconBlockRoot(ctx context.Context,
	opts *api.BeaconBlockRootOpts,
) (
	*api.Response[*phase0.Root],
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockroot.majority").Start(ctx, "BeaconBlockRoot", trace.WithAttributes(
		attribute.String("blockid", opts.Block),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, s.log, "strategy_id").With().Str("block_id", opts.Block).Logger()

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	hardCtx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)

	requests := len(s.beaconBlockRootProviders)

	respCh := make(chan *beaconBlockRootResponse, requests)
	errCh := make(chan *beaconBlockRootError, requests)
	// Kick off the requests.
	for name, provider := range s.beaconBlockRootProviders {
		go s.beaconBlockRoot(hardCtx, started, name, provider, respCh, errCh, opts)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	timedOut := 0
	softTimedOut := 0
	beaconBlockRootCounts := make(map[phase0.Root]int)
	var beaconBlockRootCountsMu sync.Mutex
	// Keep track of the highest number of votes we have for any root, as we can exit early
	// on an absolute majority.
	highestCount := 0
	absoluteMajority := requests/2 + 1

	// Loop 1: prior to soft timeout.
	for responded+errored+timedOut+softTimedOut != requests && highestCount < absoluteMajority {
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
			beaconBlockRootCountsMu.Lock()
			beaconBlockRootCounts[*resp.root]++
			if beaconBlockRootCounts[*resp.root] > highestCount {
				highestCount = beaconBlockRootCounts[*resp.root]
			}
			beaconBlockRootCountsMu.Unlock()
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
	for responded+errored+timedOut != requests && highestCount < absoluteMajority {
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
			beaconBlockRootCountsMu.Lock()
			beaconBlockRootCounts[*resp.root]++
			if beaconBlockRootCounts[*resp.root] > highestCount {
				highestCount = beaconBlockRootCounts[*resp.root]
			}
			beaconBlockRootCountsMu.Unlock()
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
		case <-hardCtx.Done():
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

	var bestRoot phase0.Root
	bestRootCount := 0
	bestRootSlot := phase0.Slot(0)
	for root, count := range beaconBlockRootCounts {
		slot, err := s.blockRootToSlotCache.BlockRootToSlot(ctx, root)
		if err != nil {
			log.Debug().Stringer("root", root).Err(err).Msg("Failed to obtain parent slot; assuming 0")
		}
		switch {
		case count > bestRootCount:
			// New majority.
			bestRoot = root
			bestRootCount = count
			bestRootSlot = slot
		case count == bestRootCount:
			// Tie, take the one with the higher slot.
			if slot > bestRootSlot {
				bestRoot = root
				bestRootSlot = slot
			}
		default:
			// Fewer votes than current; ignore.
		}
	}

	if bestRootCount == 0 {
		return nil, errors.New("no beacon block root received")
	}
	log.Trace().Stringer("root", bestRoot).Uint64("slot", uint64(bestRootSlot)).Int("count", bestRootCount).Msg("Selected majority beacon block root")

	return &api.Response[*phase0.Root]{
		Data:     &bestRoot,
		Metadata: make(map[string]any),
	}, nil
}

func (s *Service) beaconBlockRoot(ctx context.Context,
	started time.Time,
	name string,
	provider eth2client.BeaconBlockRootProvider,
	respCh chan *beaconBlockRootResponse,
	errCh chan *beaconBlockRootError,
	opts *api.BeaconBlockRootOpts,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockroot.majority").Start(ctx, "beaconBlockRoot", trace.WithAttributes(
		attribute.String("provider", name),
	))
	defer span.End()

	rootResponse, err := provider.BeaconBlockRoot(ctx, opts)
	clientprometheus.MonitorClientOperation(name, "beacon block root", err == nil, time.Since(started))
	if err != nil {
		errCh <- &beaconBlockRootError{
			provider: name,
			err:      err,
		}
		return
	}
	s.log.Trace().Str("provider", name).Dur("elapsed", time.Since(started)).Stringer("root", rootResponse.Data).Msg("Obtained beacon block root")

	respCh <- &beaconBlockRootResponse{
		provider: name,
		root:     rootResponse.Data,
	}
}
