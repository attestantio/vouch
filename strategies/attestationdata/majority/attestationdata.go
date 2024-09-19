// Copyright © 2024 Attestant Limited.
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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
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
func (s *Service) AttestationData(ctx context.Context,
	opts *api.AttestationDataOpts,
) (
	*api.Response[*phase0.AttestationData],
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.attestationdata.majority").Start(ctx, "AttestationData", trace.WithAttributes(
		attribute.Int64("slot", util.SlotToInt64(opts.Slot)),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, s.log, "strategy_id").With().Uint64("slot", uint64(opts.Slot)).Logger()
	ctx = log.WithContext(ctx)

	requests := len(s.attestationDataProviders)

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have enough data to proceed.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	hardCtx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(hardCtx, s.timeout/2)

	respCh, errCh := s.issueAttestationDataRequests(hardCtx, opts, started, requests)
	span.AddEvent("Issued requests")

	attestationData := make(map[[32]byte]*phase0.AttestationData)
	attestationDataCounts := make(map[[32]byte]int)
	attestationDataProviders := make(map[[32]byte][]string)
	responded, errored := s.attestationDataLoop1(softCtx, started, requests, attestationData, attestationDataCounts, attestationDataProviders, respCh, errCh)
	softCancel()

	s.attestationDataLoop2(hardCtx, started, requests, attestationData, attestationDataCounts, attestationDataProviders, respCh, errCh, responded, errored)
	cancel()

	var bestAttestationDataRoot [32]byte
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
			bestAttestationDataRoot = root
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
	if bestAttestationDataCount < s.threshold {
		return nil, fmt.Errorf("majority attestation data count of %d lower than threshold %d", bestAttestationDataCount, s.threshold)
	}
	slot, err := s.blockRootToSlotCache.BlockRootToSlot(ctx, bestAttestationData.BeaconBlockRoot)
	if err != nil {
		log.Debug().Stringer("root", bestAttestationData.BeaconBlockRoot).Err(err).Msg("Failed to obtain best attestation data head slot; assuming 0")
	}
	log.Trace().
		Dur("elapsed", time.Since(started)).
		Stringer("attestation_data", &bestAttestationData).
		Int64("head_distance", util.SlotToInt64(bestAttestationData.Slot)-util.SlotToInt64(slot)).
		Int("count", bestAttestationDataCount).
		Msg("Selected majority attestation data")
	for _, provider := range attestationDataProviders[bestAttestationDataRoot] {
		s.clientMonitor.StrategyOperation("majority", provider, "attestation data", time.Since(started))
	}

	return &api.Response[*phase0.AttestationData]{
		Data:     &bestAttestationData,
		Metadata: make(map[string]any),
	}, nil
}

func (s *Service) issueAttestationDataRequests(ctx context.Context,
	opts *api.AttestationDataOpts,
	started time.Time,
	requests int,
) (
	chan *attestationDataResponse,
	chan *attestationDataError,
) {
	respCh := make(chan *attestationDataResponse, requests)
	errCh := make(chan *attestationDataError, requests)

	// Kick off the requests.
	for name, provider := range s.attestationDataProviders {
		go s.attestationData(ctx, started, name, provider, respCh, errCh, opts)
	}

	return respCh, errCh
}

func (s *Service) attestationData(ctx context.Context,
	started time.Time,
	providerName string,
	provider eth2client.AttestationDataProvider,
	respCh chan *attestationDataResponse,
	errCh chan *attestationDataError,
	opts *api.AttestationDataOpts,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.attestationdata.best").Start(ctx, "attestationData", trace.WithAttributes(
		attribute.String("provider", providerName),
	))
	defer span.End()

	attestationDataResp, err := provider.AttestationData(ctx, opts)
	s.clientMonitor.ClientOperation(providerName, "attestation data", err == nil, time.Since(started))
	if err != nil {
		errCh <- &attestationDataError{
			provider: providerName,
			err:      err,
		}
		return
	}
	attestationData := attestationDataResp.Data

	if attestationData == nil {
		errCh <- &attestationDataError{
			provider: providerName,
			err:      errors.New("attestation data nil"),
		}
		return
	}
	if attestationData.Target == nil {
		errCh <- &attestationDataError{
			provider: providerName,
			err:      errors.New("attestation data target nil"),
		}
		return
	}
	if attestationData.Target.Epoch != s.chainTime.SlotToEpoch(opts.Slot) {
		errCh <- &attestationDataError{
			provider: providerName,
			err:      errors.New("attestation data slot/target epoch mismatch"),
		}
		return
	}

	respCh <- &attestationDataResponse{
		provider:        providerName,
		attestationData: attestationData,
	}
}

func (*Service) attestationDataLoop1(ctx context.Context,
	started time.Time,
	requests int,
	attestationData map[[32]byte]*phase0.AttestationData,
	attestationDataCounts map[[32]byte]int,
	attestationDataProviders map[[32]byte][]string,
	respCh chan *attestationDataResponse,
	errCh chan *attestationDataError,
) (
	int,
	int,
) {
	log := zerolog.Ctx(ctx)

	// Wait for enough responses (or context done).
	responded := 0
	errored := 0
	largestCount := 0
	strictMajority := requests/2 + 1

	for responded+errored != requests && largestCount < strictMajority {
		select {
		case resp := <-respCh:
			responded++
			log.Trace().
				Dur("elapsed", time.Since(started)).
				Str("provider", resp.provider).
				Int("responded", responded).
				Int("errored", errored).
				Msg("Response received")
			attestationDataRoot, err := resp.attestationData.HashTreeRoot()
			if err != nil {
				log.Error().Err(err).Msg("Failed to obtain root of attestation data")
			} else {
				attestationData[attestationDataRoot] = resp.attestationData
				attestationDataCounts[attestationDataRoot]++
				if attestationDataCounts[attestationDataRoot] > largestCount {
					largestCount = attestationDataCounts[attestationDataRoot]
				}
				attestationDataProviders[attestationDataRoot] = append(attestationDataProviders[attestationDataRoot], resp.provider)
			}
		case err := <-errCh:
			errored++
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Str("provider", err.provider).
				Int("responded", responded).
				Int("errored", errored).
				Err(err.err).
				Msg("Error received")
		case <-ctx.Done():
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", requests-responded-errored).
				Msg("Soft timeout reached")
			return responded, errored
		}
	}

	return responded, errored
}

func (*Service) attestationDataLoop2(ctx context.Context,
	started time.Time,
	requests int,
	attestationData map[[32]byte]*phase0.AttestationData,
	attestationDataCounts map[[32]byte]int,
	attestationDataProviders map[[32]byte][]string,
	respCh chan *attestationDataResponse,
	errCh chan *attestationDataError,
	responded int,
	errored int,
) {
	log := zerolog.Ctx(ctx)

	largestCount := 0
	for _, v := range attestationDataCounts {
		if v > largestCount {
			largestCount = v
		}
	}
	strictMajority := requests/2 + 1

	for responded+errored != requests && largestCount < strictMajority {
		select {
		case resp := <-respCh:
			responded++
			log.Trace().
				Dur("elapsed", time.Since(started)).
				Str("provider", resp.provider).
				Int("responded", responded).
				Int("errored", errored).
				Msg("Response received")
			attestationDataRoot, err := resp.attestationData.HashTreeRoot()
			if err != nil {
				log.Error().Err(err).Msg("Failed to obtain root of attestation data")
			} else {
				attestationData[attestationDataRoot] = resp.attestationData
				attestationDataCounts[attestationDataRoot]++
				if attestationDataCounts[attestationDataRoot] > largestCount {
					largestCount = attestationDataCounts[attestationDataRoot]
				}
				attestationDataProviders[attestationDataRoot] = append(attestationDataProviders[attestationDataRoot], resp.provider)
			}
		case err := <-errCh:
			errored++
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Str("provider", err.provider).
				Int("responded", responded).
				Int("errored", errored).
				Err(err.err).
				Msg("Error received")
		case <-ctx.Done():
			// Anyone not responded by now is timed out.
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", requests-responded-errored).
				Msg("Hard timeout reached")
			return
		}
	}

	log.Trace().
		Dur("elapsed", time.Since(started)).
		Int("responded", responded).
		Int("errored", errored).
		Msg("Results")
}
