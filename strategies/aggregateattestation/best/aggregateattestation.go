// Copyright © 2020, 2022 Attestant Limited.
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
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type aggregateAttestationResponse struct {
	provider  string
	aggregate *phase0.Attestation
	score     float64
}

type aggregateAttestationError struct {
	provider string
	err      error
}

// AggregateAttestation provides the aggregate attestation from a number of beacon nodes.
func (s *Service) AggregateAttestation(ctx context.Context, slot phase0.Slot, attestationDataRoot phase0.Root) (*phase0.Attestation, error) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.aggregateattestation.best").Start(ctx, "AggregateAttestation", trace.WithAttributes(
		attribute.Int64("slot", int64(slot)),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, log, "strategy_id")

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)

	requests := len(s.aggregateAttestationProviders)

	respCh := make(chan *aggregateAttestationResponse, requests)
	errCh := make(chan *aggregateAttestationError, requests)
	// Kick off the requests.
	for name, provider := range s.aggregateAttestationProviders {
		go s.aggregateAttestation(ctx, started, name, provider, respCh, errCh, slot, attestationDataRoot)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	timedOut := 0
	softTimedOut := 0
	bestScore := float64(0)
	var bestAggregateAttestation *phase0.Attestation
	bestProvider := ""

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
			if bestAggregateAttestation == nil || resp.score > bestScore {
				bestAggregateAttestation = resp.aggregate
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
			if bestAggregateAttestation == nil || resp.score > bestScore {
				bestAggregateAttestation = resp.aggregate
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

	if bestAggregateAttestation == nil {
		return nil, errors.New("no aggregate attestations received")
	}
	log.Trace().
		Str("provider", bestProvider).
		Stringer("aggregate_attestation", bestAggregateAttestation).
		Float64("score", bestScore).
		Msg("Selected best aggregate attestation")
	if bestProvider != "" {
		s.clientMonitor.StrategyOperation("best", bestProvider, "aggregate attestation", time.Since(started))
	}

	return bestAggregateAttestation, nil
}

func (s *Service) aggregateAttestation(ctx context.Context,
	started time.Time,
	name string,
	provider eth2client.AggregateAttestationProvider,
	respCh chan *aggregateAttestationResponse,
	errCh chan *aggregateAttestationError,
	slot phase0.Slot,
	attestationDataRoot phase0.Root,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.aggregateattestation.best").Start(ctx, "aggregateAttestation", trace.WithAttributes(
		attribute.String("provider", name),
	))
	defer span.End()

	aggregate, err := provider.AggregateAttestation(ctx, slot, attestationDataRoot)
	s.clientMonitor.ClientOperation(name, "aggregate attestation", err == nil, time.Since(started))
	if err != nil {
		errCh <- &aggregateAttestationError{
			provider: name,
			err:      err,
		}
		return
	}
	log.Trace().Str("provider", name).Dur("elapsed", time.Since(started)).Msg("Obtained aggregate attestation")
	if aggregate == nil {
		errCh <- &aggregateAttestationError{
			provider: name,
			err:      errors.New("aggregate attestation nil"),
		}
		return
	}

	score := s.scoreAggregateAttestation(ctx, name, aggregate)
	respCh <- &aggregateAttestationResponse{
		provider:  name,
		aggregate: aggregate,
		score:     score,
	}
}
