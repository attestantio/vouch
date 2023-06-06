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

type attestationDataResponse struct {
	provider        string
	attestationData *phase0.AttestationData
	score           float64
}

type attestationDataError struct {
	provider string
	err      error
}

// AttestationData provides the best attestation data from a number of beacon nodes.
func (s *Service) AttestationData(ctx context.Context, slot phase0.Slot, committeeIndex phase0.CommitteeIndex) (*phase0.AttestationData, error) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.attestationdata.best").Start(ctx, "AttestationData", trace.WithAttributes(
		attribute.Int64("slot", int64(slot)),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, log, "strategy_id").With().Uint64("slot", uint64(slot)).Logger()

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)

	requests := len(s.attestationDataProviders)

	respCh := make(chan *attestationDataResponse, requests)
	errCh := make(chan *attestationDataError, requests)
	// Kick off the requests.
	for name, provider := range s.attestationDataProviders {
		go s.attestationData(ctx, started, name, provider, respCh, errCh, slot, committeeIndex)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	timedOut := 0
	softTimedOut := 0
	bestScore := float64(0)
	var bestAttestationData *phase0.AttestationData
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
			if bestAttestationData == nil || resp.score > bestScore {
				bestAttestationData = resp.attestationData
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
			if bestAttestationData == nil || resp.score > bestScore {
				bestAttestationData = resp.attestationData
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

	if bestAttestationData == nil {
		return nil, errors.New("no attestations received")
	}
	log.Trace().Str("provider", bestProvider).Stringer("attestation_data", bestAttestationData).Float64("score", bestScore).Msg("Selected best attestation")
	if bestProvider != "" {
		s.clientMonitor.StrategyOperation("best", bestProvider, "attestation data", time.Since(started))
	}

	return bestAttestationData, nil
}

func (s *Service) attestationData(ctx context.Context,
	started time.Time,
	name string,
	provider eth2client.AttestationDataProvider,
	respCh chan *attestationDataResponse,
	errCh chan *attestationDataError,
	slot phase0.Slot,
	committeeIndex phase0.CommitteeIndex,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.attestationdata.best").Start(ctx, "attestationData", trace.WithAttributes(
		attribute.String("provider", name),
	))
	defer span.End()

	attestationData, err := provider.AttestationData(ctx, slot, committeeIndex)
	s.clientMonitor.ClientOperation(name, "attestation data", err == nil, time.Since(started))
	if err != nil {
		errCh <- &attestationDataError{
			provider: name,
			err:      err,
		}
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained attestation data")

	if attestationData == nil {
		errCh <- &attestationDataError{
			provider: name,
			err:      errors.New("attestation data nil"),
		}
		return
	}
	if attestationData.Target == nil {
		errCh <- &attestationDataError{
			provider: name,
			err:      errors.New("attestation data target nil"),
		}
		return
	}
	if attestationData.Target.Epoch != s.chainTime.SlotToEpoch(slot) {
		errCh <- &attestationDataError{
			provider: name,
			err:      errors.New("attestation data slot/target epoch mismatch"),
		}
		return
	}

	score := s.scoreAttestationData(ctx, name, attestationData)
	respCh <- &attestationDataResponse{
		provider:        name,
		attestationData: attestationData,
		score:           score,
	}
}
