// Copyright © 2023 - 2025 Attestant Limited.
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
	"encoding/json"
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

	attestationDataResponses := make(map[phase0.Root][]*attestationDataResponse)
	responded, errored := s.attestationDataLoop1(softCtx, started, requests, attestationDataResponses, respCh, errCh)
	softCancel()

	s.attestationDataLoop2(hardCtx, started, requests, attestationDataResponses, respCh, errCh, responded, errored)
	cancel()

	bestAttestationData, err := s.selectAttestationData(ctx, started, attestationDataResponses)
	if err != nil {
		return nil, err
	}

	return &api.Response[*phase0.AttestationData]{
		Data:     bestAttestationData,
		Metadata: make(map[string]any),
	}, nil
}

func (s *Service) selectAttestationData(ctx context.Context,
	started time.Time,
	attestationDataResponses map[phase0.Root][]*attestationDataResponse,
) (
	*phase0.AttestationData,
	error,
) {
	// Start off by obtaining the majority attestation data response.
	majorityAttestationDataResponses := s.majorityAttestationDataResponse(ctx, started, attestationDataResponses)
	majorityCount := len(majorityAttestationDataResponses)

	if majorityCount == 0 {
		monitorAttestationData("no responses")

		return nil, errors.New("no attestation data received")
	}
	bestAttestationData := majorityAttestationDataResponses[0].attestationData

	if majorityCount >= s.threshold {
		monitorAttestationData("threshold")

		return bestAttestationData, nil
	}

	// If we reach here there is no outright majority.
	if !s.recombination {
		monitorAttestationData("threshold not met")

		return nil, fmt.Errorf("majority of %d does not satisfy threshold %d", majorityCount, s.threshold)
	}

	// Attempt to recombine responses into partial consensus attestation data.
	bestAttestationData, err := s.recombineAttestationData(ctx, started, attestationDataResponses)
	if err != nil {
		monitorAttestationData("recombination threshold not met")

		return nil, err
	}
	monitorAttestationData("recombination")

	return bestAttestationData, nil
}

func (s *Service) majorityAttestationDataResponse(ctx context.Context,
	started time.Time,
	attestationDataResponses map[phase0.Root][]*attestationDataResponse,
) []*attestationDataResponse {
	log := zerolog.Ctx(ctx)

	bestAttestationDataSlot := phase0.Slot(0)
	var bestResponses []*attestationDataResponse
	for _, responses := range attestationDataResponses {
		count := len(responses)
		slot, err := s.blockRootToSlotCache.BlockRootToSlot(ctx, responses[0].attestationData.BeaconBlockRoot)
		if err != nil {
			log.Debug().Stringer("root", responses[0].attestationData.BeaconBlockRoot).Err(err).Msg("Failed to obtain attestation data head slot; assuming 0")
		}
		switch {
		case count > len(bestResponses):
			// New majority.
			bestResponses = responses
			bestAttestationDataSlot = slot
		case count == len(bestResponses):
			// Tie, take the one with the higher slot.
			if slot > bestAttestationDataSlot {
				bestAttestationDataSlot = slot
				bestResponses = responses
			}
		default:
			// Fewer votes than current; ignore.
		}
	}

	if len(bestResponses) < s.threshold {
		// Log out all of the attestations in this situation, to help understand what went wrong.
		for _, responses := range attestationDataResponses {
			providers := make([]string, 0, len(responses))
			for _, response := range responses {
				providers = append(providers, response.provider)
			}
			data, err := json.Marshal(responses[0].attestationData)
			if err == nil {
				log.Debug().Strs("providers", providers).RawJSON("data", data).Msg("Non-majority attestation response received")
			}
		}
	} else {
		bestAttestationData := bestResponses[0].attestationData

		for _, response := range bestResponses {
			s.clientMonitor.StrategyOperation("majority", response.provider, "attestation data", time.Since(started))
		}

		slot, err := s.blockRootToSlotCache.BlockRootToSlot(ctx, bestAttestationData.BeaconBlockRoot)
		if err != nil {
			log.Debug().Stringer("root", bestAttestationData.BeaconBlockRoot).Err(err).Msg("Failed to obtain best attestation data head slot; assuming 0")
		}

		log.Trace().
			Dur("elapsed", time.Since(started)).
			Stringer("attestation_data", bestAttestationData).
			Int64("head_distance", util.SlotToInt64(bestAttestationData.Slot)-util.SlotToInt64(slot)).
			Int("count", len(bestResponses)).
			Msg("Selected majority attestation data")
	}

	return bestResponses
}

// recombineAttestationData attempts to combine non-consensus attestation data responses into a consensus response.
// It does this by picking out individual elements (source, target) on which there is consensus.
func (s *Service) recombineAttestationData(ctx context.Context,
	started time.Time,
	attestationDataResponses map[phase0.Root][]*attestationDataResponse,
) (
	*phase0.AttestationData,
	error,
) {
	log := zerolog.Ctx(ctx)

	builtAttestationData := &phase0.AttestationData{
		Source: &phase0.Checkpoint{},
		Target: &phase0.Checkpoint{},
	}

	sources := make(map[phase0.Root]int)
	sourceEpochs := make(map[phase0.Root]phase0.Epoch)
	targets := make(map[phase0.Root]int)
	targetEpochs := make(map[phase0.Root]phase0.Epoch)

	for _, responses := range attestationDataResponses {
		attestationData := responses[0].attestationData

		builtAttestationData.Slot = attestationData.Slot
		builtAttestationData.Index = attestationData.Index
		sources[attestationData.Source.Root] += len(responses)
		sourceEpochs[attestationData.Source.Root] = attestationData.Source.Epoch
		targets[attestationData.Target.Root] += len(responses)
		targetEpochs[attestationData.Target.Root] = attestationData.Target.Epoch
	}

	for sourceRoot, count := range sources {
		if count >= s.threshold {
			builtAttestationData.Source.Root = sourceRoot
			builtAttestationData.Source.Epoch = sourceEpochs[sourceRoot]
			break
		}
	}
	if builtAttestationData.Source.Epoch == 0 {
		// We cannot proceed here as this is a potentially slashable attestation.
		log.Debug().Msg("Attempt to build attestation data resulted in no source checkpoint; aborting")

		return nil, errors.New("could not build majority attestation data; no source checkpoint")
	}

	for targetRoot, count := range targets {
		if count >= s.threshold {
			builtAttestationData.Target.Root = targetRoot
			builtAttestationData.Target.Epoch = targetEpochs[targetRoot]
			break
		}
	}
	if builtAttestationData.Target.Epoch == 0 {
		// We cannot proceed here as this is a potentially slashable attestation.
		log.Debug().Msg("Attempt to build attestation data resulted in no target checkpoint; aborting")

		return nil, errors.New("could not build majority attestation data; no target checkpoint")
	}

	log.Trace().
		Dur("elapsed", time.Since(started)).
		Stringer("attestation_data", builtAttestationData).
		Msg("Recombined majority attestation data")

	return builtAttestationData, nil
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
	attestationDataResponses map[phase0.Root][]*attestationDataResponse,
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
				continue
			}
			if _, exists := attestationDataResponses[attestationDataRoot]; !exists {
				attestationDataResponses[attestationDataRoot] = make([]*attestationDataResponse, 0)
			}
			attestationDataResponses[attestationDataRoot] = append(attestationDataResponses[attestationDataRoot], resp)
			if len(attestationDataResponses[attestationDataRoot]) > largestCount {
				largestCount = len(attestationDataResponses[attestationDataRoot])
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
	attestationDataResponses map[phase0.Root][]*attestationDataResponse,
	respCh chan *attestationDataResponse,
	errCh chan *attestationDataError,
	responded int,
	errored int,
) {
	log := zerolog.Ctx(ctx)

	largestCount := 0
	for _, responses := range attestationDataResponses {
		if len(responses) > largestCount {
			largestCount = len(responses)
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
				continue
			}
			if _, exists := attestationDataResponses[attestationDataRoot]; !exists {
				attestationDataResponses[attestationDataRoot] = make([]*attestationDataResponse, 0)
			}
			attestationDataResponses[attestationDataRoot] = append(attestationDataResponses[attestationDataRoot], resp)
			if len(attestationDataResponses[attestationDataRoot]) > largestCount {
				largestCount = len(attestationDataResponses[attestationDataRoot])
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
