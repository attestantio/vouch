// Copyright © 2020 - 2022 Attestant Limited.
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
	"bytes"
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type beaconBlockResponse struct {
	provider string
	proposal *api.VersionedProposal
	score    float64
}

type beaconBlockError struct {
	provider string
	err      error
}

// Proposal provides the best beacon block proposal from a number of beacon nodes.
func (s *Service) Proposal(ctx context.Context,
	opts *api.ProposalOpts,
) (
	*api.Response[*api.VersionedProposal],
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockproposal.best").Start(ctx, "Proposal", trace.WithAttributes(
		attribute.Int64("slot", int64(opts.Slot)),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, log, "strategy_id").With().Uint64("slot", uint64(opts.Slot)).Logger()

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)

	requests := len(s.proposalProviders)

	respCh := make(chan *beaconBlockResponse, requests)
	errCh := make(chan *beaconBlockError, requests)
	// Kick off the requests.
	for name, provider := range s.proposalProviders {
		providerGraffiti := opts.Graffiti[:]
		if bytes.Contains(providerGraffiti, []byte("{{CLIENT}}")) {
			if nodeClientProvider, isProvider := provider.(eth2client.NodeClientProvider); isProvider {
				nodeClientResponse, err := nodeClientProvider.NodeClient(ctx)
				if err != nil {
					log.Warn().Err(err).Msg("Failed to obtain node client; not updating graffiti")
				} else {
					providerGraffiti = bytes.ReplaceAll(providerGraffiti, []byte("{{CLIENT}}"), []byte(nodeClientResponse.Data))
				}
				if len(providerGraffiti) > 32 {
					providerGraffiti = providerGraffiti[0:32]
				}
				// Replace entire opts structure so the mutated graffiti does not leak to other providers.
				opts = &api.ProposalOpts{
					Slot:                   opts.Slot,
					RandaoReveal:           opts.RandaoReveal,
					Graffiti:               [32]byte(providerGraffiti),
					SkipRandaoVerification: opts.SkipRandaoVerification,
				}
			}
		}
		go s.beaconBlockProposal(ctx, started, name, provider, respCh, errCh, opts)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	timedOut := 0
	softTimedOut := 0
	bestScore := float64(0)
	var bestProposal *api.VersionedProposal
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
			if bestProposal == nil || resp.score > bestScore {
				bestProposal = resp.proposal
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
			if bestProposal == nil || resp.score > bestScore {
				bestProposal = resp.proposal
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

	if bestProposal == nil {
		return nil, errors.New("no proposals received")
	}
	log.Trace().Str("provider", bestProvider).Stringer("proposal", bestProposal).Float64("score", bestScore).Dur("elapsed", time.Since(started)).Msg("Selected best proposal")
	if bestProvider != "" {
		s.clientMonitor.StrategyOperation("best", bestProvider, "beacon block proposal", time.Since(started))
	}

	return &api.Response[*api.VersionedProposal]{
		Data:     bestProposal,
		Metadata: make(map[string]any),
	}, nil
}

func (s *Service) beaconBlockProposal(ctx context.Context,
	started time.Time,
	name string,
	provider eth2client.ProposalProvider,
	respCh chan *beaconBlockResponse,
	errCh chan *beaconBlockError,
	opts *api.ProposalOpts,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockproposal.best").Start(ctx, "beaconBlockProposal", trace.WithAttributes(
		attribute.String("provider", name),
	))
	defer span.End()

	proposalResponse, err := provider.Proposal(ctx, opts)
	s.clientMonitor.ClientOperation(name, "beacon block proposal", err == nil, time.Since(started))
	if err != nil {
		errCh <- &beaconBlockError{
			provider: name,
			err:      err,
		}

		return
	}
	proposal := proposalResponse.Data
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained beacon block proposal")

	if proposal.Version != spec.DataVersionPhase0 &&
		proposal.Version != spec.DataVersionAltair {
		feeRecipient, err := proposal.FeeRecipient()
		if err != nil {
			errCh <- &beaconBlockError{
				provider: name,
				err:      errors.Wrap(err, "failed to obtain fee recipient for beacon block"),
			}

			return
		}
		if feeRecipient.IsZero() {
			errCh <- &beaconBlockError{
				provider: name,
				err:      errors.New("beacon block obtained with 0 fee recipient"),
			}

			return
		}
	}

	score := s.scoreBeaconBlockProposal(ctx, name, proposal)
	span.SetAttributes(attribute.Float64("score", score))
	respCh <- &beaconBlockResponse{
		provider: name,
		proposal: proposal,
		score:    score,
	}
}
