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
	"fmt"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
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
}

type attestationDataError struct {
	provider string
	err      error
}

// AttestationData provides the consensus attestation data from a number of beacon nodes.
//
//nolint:maintidx
func (s *Service) AttestationData(ctx context.Context,
	opts *api.AttestationDataOpts,
) (
	*api.Response[*phase0.AttestationData],
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.attestationdata.majority").Start(ctx, "AttestationData", trace.WithAttributes(
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

	requests := len(s.attestationDataProviders)

	respCh := make(chan *attestationDataResponse, requests)
	errCh := make(chan *attestationDataError, requests)
	// Kick off the requests.
	for name, provider := range s.attestationDataProviders {
		go s.attestationData(ctx, started, name, provider, respCh, errCh, opts)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	timedOut := 0
	softTimedOut := 0
	attestationData := make(map[[32]byte]*phase0.AttestationData)
	attestationDataCounts := make(map[[32]byte]int)
	largestCount := 0
	strictMajority := requests/2 + 1
	var attestationDataCountsMu sync.Mutex

	// Loop 1: prior to soft timeout.
	for responded+errored+timedOut+softTimedOut != requests && largestCount < strictMajority {
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
			attestationDataRoot, err := resp.attestationData.HashTreeRoot()
			if err != nil {
				log.Error().Err(err).Msg("Failed to obtain root of attestation data")
			} else {
				attestationDataCountsMu.Lock()
				attestationData[attestationDataRoot] = resp.attestationData
				attestationDataCounts[attestationDataRoot]++
				if attestationDataCounts[attestationDataRoot] > largestCount {
					largestCount = attestationDataCounts[attestationDataRoot]
				}
				attestationDataCountsMu.Unlock()
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
	for responded+errored+timedOut != requests && largestCount < strictMajority {
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
			attestationDataRoot, err := resp.attestationData.HashTreeRoot()
			if err != nil {
				log.Error().Err(err).Msg("Failed to obtain root of attestation data")
			} else {
				attestationDataCountsMu.Lock()
				attestationData[attestationDataRoot] = resp.attestationData
				attestationDataCounts[attestationDataRoot]++
				if attestationDataCounts[attestationDataRoot] > largestCount {
					largestCount = attestationDataCounts[attestationDataRoot]
				}
				attestationDataCountsMu.Unlock()
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
			// Anyone not responded by now is timed out.
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
	if largestCount >= strictMajority && largestCount >= int(s.threshold) {
		log.Trace().Msg("Strict majority reached")
		timedOut = requests - responded - errored
	}
	log.Trace().
		Dur("elapsed", time.Since(started)).
		Int("responded", responded).
		Int("errored", errored).
		Int("timed_out", timedOut).
		Msg("Results")

	var bestAttestationData phase0.AttestationData
	bestAttestationDataCount := 0
	bestAttestationDataSlot := phase0.Slot(0)
	for root, attestationData := range attestationData {
		count := attestationDataCounts[root]
		slot, err := s.blockRootToSlotCache.BlockRootToSlot(ctx, attestationData.BeaconBlockRoot)
		if err != nil {
			log.Debug().Stringer("root", attestationData.BeaconBlockRoot).Err(err).Msg("Failed to obtain attestation data head slot; assuming 0")
		}
		switch {
		case count > bestAttestationDataCount:
			// New majority.
			bestAttestationData = *attestationData
			bestAttestationDataCount = count
			bestAttestationDataSlot = slot
		case count == bestAttestationDataCount:
			// Tie, take the one with the higher slot.
			if slot > bestAttestationDataSlot {
				bestAttestationData = *attestationData
				bestAttestationDataSlot = slot
			}
		default:
			// Fewer votes than current; ignore.
		}
	}

	if bestAttestationDataCount == 0 {
		return nil, errors.New("no attestation data received")
	}
	if bestAttestationDataCount < int(s.threshold) {
		return nil, fmt.Errorf("majority attestation data count of %d lower than threshold %d", bestAttestationDataCount, s.threshold)
	}
	slot, err := s.blockRootToSlotCache.BlockRootToSlot(ctx, bestAttestationData.BeaconBlockRoot)
	if err == nil {
		log.Trace().Uint64("slot", uint64(bestAttestationData.Slot)).Stringer("head", bestAttestationData.BeaconBlockRoot).Int("head_distance", int(bestAttestationData.Slot-slot)).Msg("Attestation slot data")
	}
	log.Trace().Stringer("attestation_data", &bestAttestationData).Int("count", bestAttestationDataCount).Msg("Selected majority attestation data")

	return &api.Response[*phase0.AttestationData]{
		Data:     &bestAttestationData,
		Metadata: make(map[string]any),
	}, nil
}

func (s *Service) attestationData(ctx context.Context,
	started time.Time,
	name string,
	provider eth2client.AttestationDataProvider,
	respCh chan *attestationDataResponse,
	errCh chan *attestationDataError,
	opts *api.AttestationDataOpts,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.attestationdata.best").Start(ctx, "attestationData", trace.WithAttributes(
		attribute.String("provider", name),
	))
	defer span.End()

	attestationDataResp, err := provider.AttestationData(ctx, opts)
	s.clientMonitor.ClientOperation(name, "attestation data", err == nil, time.Since(started))
	if err != nil {
		errCh <- &attestationDataError{
			provider: name,
			err:      err,
		}
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained attestation data")
	attestationData := attestationDataResp.Data

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
	if attestationData.Target.Epoch != s.chainTime.SlotToEpoch(opts.Slot) {
		errCh <- &attestationDataError{
			provider: name,
			err:      errors.New("attestation data slot/target epoch mismatch"),
		}
		return
	}

	respCh <- &attestationDataResponse{
		provider:        name,
		attestationData: attestationData,
	}
}
