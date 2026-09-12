// Copyright © 2020 - 2026 Attestant Limited.
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
	"math/big"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/strategies/beaconblockproposal"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
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
	provider        string
	err             error
	elapsed         time.Duration
	outcome         string
	rejectionReason string
}

type beaconBlockProposalResults struct {
	bestProvider string
	responded    int
	errored      int
	timedOut     int
	bestScore    float64
	bestProposal *api.VersionedProposal
}

func waitForProposalResponses(ctx context.Context,
	softCtx context.Context,
	softCancel context.CancelFunc,
	started time.Time,
	requests int,
	respCh <-chan *beaconBlockResponse,
	errCh <-chan *beaconBlockError,
	log zerolog.Logger,
) *beaconBlockProposalResults {
	results := &beaconBlockProposalResults{}
	softTimedOut := 0

	// Wait for responses prior to the soft timeout.
	for results.responded+results.errored+results.timedOut+softTimedOut != requests {
		select {
		case response := <-respCh:
			results.responded++
			log.Trace().
				Dur("elapsed", time.Since(started)).
				Str("provider", response.provider).
				Int("responded", results.responded).
				Int("errored", results.errored).
				Int("timed_out", results.timedOut).
				Msg("Response received")
			if results.bestProposal == nil || response.score > results.bestScore {
				results.bestProposal = response.proposal
				results.bestScore = response.score
				results.bestProvider = response.provider
			}
		case proposalErr := <-errCh:
			results.errored++
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Str("provider", proposalErr.provider).
				Int("responded", results.responded).
				Int("errored", results.errored).
				Int("timed_out", results.timedOut).
				Err(proposalErr.err).
				Msg("Error received")
		case <-softCtx.Done():
			if results.responded > 0 {
				results.timedOut = requests - results.responded - results.errored
				log.Debug().
					Dur("elapsed", time.Since(started)).
					Int("responded", results.responded).
					Int("errored", results.errored).
					Int("timed_out", results.timedOut).
					Msg("Soft timeout reached with responses")
			} else {
				log.Debug().
					Dur("elapsed", time.Since(started)).
					Int("errored", results.errored).
					Msg("Soft timeout reached with no responses")
			}
			softTimedOut = requests - results.responded - results.errored - results.timedOut
		}
	}
	softCancel()

	// Wait for responses after the soft timeout.
	for results.responded+results.errored+results.timedOut != requests {
		select {
		case response := <-respCh:
			results.responded++
			log.Trace().
				Dur("elapsed", time.Since(started)).
				Str("provider", response.provider).
				Int("responded", results.responded).
				Int("errored", results.errored).
				Int("timed_out", results.timedOut).
				Msg("Response received")
			if results.bestProposal == nil || response.score > results.bestScore {
				results.bestProposal = response.proposal
				results.bestScore = response.score
				results.bestProvider = response.provider
			}
		case proposalErr := <-errCh:
			results.errored++
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Str("provider", proposalErr.provider).
				Int("responded", results.responded).
				Int("errored", results.errored).
				Int("timed_out", results.timedOut).
				Err(proposalErr.err).
				Msg("Error received")
		case <-ctx.Done():
			results.timedOut = requests - results.responded - results.errored
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Int("responded", results.responded).
				Int("errored", results.errored).
				Int("timed_out", results.timedOut).
				Msg("Hard timeout reached")
		}
	}

	return results
}

// EPBSProposal provides the best ePBS proposal from a number of beacon nodes.
func (s *Service) EPBSProposal(ctx context.Context,
	opts *api.EPBSProposalOpts,
) (
	*api.Response[*api.VersionedEPBSProposal],
	error,
) {
	ctx, requestID := beaconblockproposer.EnsureRequestID(ctx)
	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockproposal.best").Start(ctx, "EPBSProposal", trace.WithAttributes(
		attribute.Int64("slot", util.SlotToInt64(opts.Slot)),
		attribute.String("request_id", requestID),
		attribute.String("provider", "unknown"),
		attribute.String("proposal_root", "unknown"),
		attribute.String("source", "unknown"),
	))
	defer span.End()

	started := time.Now()
	log := s.log.With().Str("request_id", requestID).Uint64("slot", uint64(opts.Slot)).Logger()
	ctx = log.WithContext(ctx)
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)
	defer softCancel()

	requests := len(s.proposalProviders)
	respCh := make(chan *beaconBlockEPBSResponse, requests)
	errCh := make(chan *beaconBlockError, requests)
	pendingProviders := make(map[string]struct{}, requests)
	for name, provider := range s.proposalProviders {
		pendingProviders[name] = struct{}{}
		providerOpts := *opts
		go s.epbsProposal(ctx, started, name, provider, respCh, errCh, &providerOpts, log)
	}

	responded := 0
	errored := 0
	timedOut := 0
	softTimedOut := 0
	softDeadlineReached := false
	hardDeadlineReached := false
	var bestProposal *api.VersionedEPBSProposal
	var bestProvider string
	var bestMetadata map[string]any
	for responded+errored+timedOut+softTimedOut != requests {
		select {
		case response := <-respCh:
			responded++
			delete(pendingProviders, response.provider)
			previousBest := bestProposal
			bestProposal, bestProvider = s.considerEPBSProposal(opts, response, bestProposal, bestProvider, log)
			if bestProposal == response.proposal && bestProposal != previousBest {
				bestMetadata = response.metadata
			}
			outcome := "accepted"
			if response.rejectionReason != "" {
				outcome = "rejected"
			}
			s.logEPBSProviderResult(opts.Slot, requestID, response, outcome, response.rejectionReason)
		case err := <-errCh:
			errored++
			delete(pendingProviders, err.provider)
			s.logEPBSProviderError(opts.Slot, requestID, err)
		case <-softCtx.Done():
			softDeadlineReached = true
			if bestProposal != nil {
				timedOut = requests - responded - errored
				for provider := range pendingProviders {
					s.logEPBSProviderTimeout(opts.Slot, requestID, provider, time.Since(started), "soft_deadline_reached")
					delete(pendingProviders, provider)
				}
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
					Msg("Soft timeout reached with no valid responses")
			}
			softTimedOut = requests - responded - errored - timedOut
		}
	}
	softCancel()

	for responded+errored+timedOut != requests {
		select {
		case response := <-respCh:
			responded++
			delete(pendingProviders, response.provider)
			previousBest := bestProposal
			bestProposal, bestProvider = s.considerEPBSProposal(opts, response, bestProposal, bestProvider, log)
			if bestProposal == response.proposal && bestProposal != previousBest {
				bestMetadata = response.metadata
			}
			outcome := "accepted"
			if response.rejectionReason != "" {
				outcome = "rejected"
			}
			s.logEPBSProviderResult(opts.Slot, requestID, response, outcome, response.rejectionReason)
		case err := <-errCh:
			errored++
			delete(pendingProviders, err.provider)
			s.logEPBSProviderError(opts.Slot, requestID, err)
		case <-ctx.Done():
			hardDeadlineReached = true
			timedOut = requests - responded - errored
			for provider := range pendingProviders {
				s.logEPBSProviderTimeout(opts.Slot, requestID, provider, time.Since(started), "deadline_reached")
				delete(pendingProviders, provider)
			}
		}
	}

	hardDeadlineReached = hardDeadlineReached || errors.Is(ctx.Err(), context.DeadlineExceeded)
	if bestProposal == nil {
		outcome := "no_valid_proposal"
		if hardDeadlineReached {
			outcome = "timeout"
		}
		log.Info().
			Uint64("slot", uint64(opts.Slot)).
			Str("request_id", requestID).
			Str("provider", "unknown").
			Str("proposal_root", "unknown").
			Dur("elapsed", time.Since(started)).
			Int("responded", responded).
			Int("errored", errored).
			Int("timed_out", timedOut).
			Bool("deadline_reached", hardDeadlineReached).
			Bool("soft_deadline_reached", softDeadlineReached).
			Bool("hard_deadline_reached", hardDeadlineReached).
			Str("outcome", outcome).
			Msg("ePBS proposal selection completed")
		return nil, errors.New("no ePBS proposals received")
	}
	valueKnown := bestProposal.Value() != nil
	source := beaconblockproposal.EPBSProposalSource(bestProposal, bestMetadata)
	stableBestProvider := beaconblockproposer.StableProviderName(bestProvider)
	if proposalRoot, err := bestProposal.Root(); err == nil {
		span.SetAttributes(attribute.String("proposal_root", proposalRoot.String()))
	}
	span.SetAttributes(
		attribute.String("provider", stableBestProvider),
		attribute.String("source", source),
		attribute.Bool("value_known", valueKnown),
		attribute.Bool("fallback", !valueKnown),
		attribute.Bool("soft_deadline_reached", softDeadlineReached),
		attribute.Bool("hard_deadline_reached", hardDeadlineReached),
	)
	if bestProvider != "" {
		s.clientMonitor.StrategyOperation("best", bestProvider, "ePBS beacon block proposal", time.Since(started))
	}

	metadata := make(map[string]any, 4)
	metadata[beaconblockproposer.MetadataStrategy] = "best"
	metadata[beaconblockproposer.MetadataProvider] = stableBestProvider
	metadata[beaconblockproposer.MetadataSource] = source
	metadata[beaconblockproposer.MetadataFallback] = !valueKnown
	return &api.Response[*api.VersionedEPBSProposal]{
		Data:     bestProposal,
		Metadata: metadata,
	}, nil
}

// considerEPBSProposal updates the best proposal seen so far, ignoring builder-backed proposals
// from providers without current preferences.
func (s *Service) considerEPBSProposal(opts *api.EPBSProposalOpts,
	response *beaconBlockEPBSResponse,
	bestProposal *api.VersionedEPBSProposal,
	bestProvider string,
	log zerolog.Logger,
) (*api.VersionedEPBSProposal, string) {
	if err := beaconblockproposal.ValidateBuilderBidReadiness(s.providerReadiness, response.provider, opts.Slot, response.proposal); err != nil {
		log.Warn().Str("provider", beaconblockproposer.StableProviderName(response.provider)).Msg("Discarding builder-backed ePBS proposal from provider without current preferences")
		response.rejectionReason = beaconblockproposal.RejectionReason(err)

		return bestProposal, bestProvider
	}

	if bestProposal == nil {
		return response.proposal, response.provider
	}

	value := response.proposal.Value()
	bestValue := bestProposal.Value()
	if value != nil && (bestValue == nil || value.Cmp(bestValue) > 0) {
		return response.proposal, response.provider
	}

	return bestProposal, bestProvider
}

type beaconBlockEPBSResponse struct {
	provider        string
	proposal        *api.VersionedEPBSProposal
	metadata        map[string]any
	elapsed         time.Duration
	rejectionReason string
}

func (s *Service) epbsProposal(ctx context.Context,
	started time.Time,
	name string,
	provider eth2client.MultiForkProposalProvider,
	respCh chan *beaconBlockEPBSResponse,
	errCh chan *beaconBlockError,
	opts *api.EPBSProposalOpts,
	log zerolog.Logger,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockproposal.best").Start(ctx, "ePBSBeaconBlockProposal", trace.WithAttributes(
		attribute.Int64("slot", util.SlotToInt64(opts.Slot)),
		attribute.String("request_id", beaconblockproposer.RequestID(ctx)),
		attribute.String("provider", beaconblockproposer.StableProviderName(name)),
		attribute.String("proposal_root", "unknown"),
		attribute.String("source", "unknown"),
	))
	defer span.End()

	providerGraffiti, err := beaconblockproposal.GraffitiForProvider(ctx, provider, opts.Graffiti)
	if err != nil {
		log.Warn().Msg("Failed to obtain node client; not updating graffiti")
	}
	opts.Graffiti = providerGraffiti

	providerStarted := time.Now()
	proposalResponse, err := provider.EPBSProposal(ctx, opts)
	s.clientMonitor.ClientOperation(name, "ePBS beacon block proposal", err == nil, time.Since(started))
	if err != nil {
		outcome := "error"
		rejectionReason := "provider_error"
		if errors.Is(err, context.DeadlineExceeded) {
			outcome = "timeout"
			rejectionReason = "deadline_reached"
		}
		errCh <- &beaconBlockError{
			provider:        name,
			err:             err,
			elapsed:         time.Since(providerStarted),
			outcome:         outcome,
			rejectionReason: rejectionReason,
		}

		return
	}

	if proposalResponse == nil || proposalResponse.Data == nil {
		errCh <- &beaconBlockError{
			provider:        name,
			err:             errors.New("beacon node returned no ePBS proposal"),
			elapsed:         time.Since(providerStarted),
			outcome:         "rejected",
			rejectionReason: "empty_response",
		}

		return
	}

	if err := beaconblockproposal.ValidateEPBSProposal(proposalResponse.Data, opts.IncludePayload); err != nil {
		errCh <- &beaconBlockError{
			provider:        name,
			err:             err,
			elapsed:         time.Since(providerStarted),
			outcome:         "rejected",
			rejectionReason: beaconblockproposal.RejectionReason(err),
		}

		return
	}

	source := beaconblockproposal.EPBSProposalSource(proposalResponse.Data, proposalResponse.Metadata)
	span.SetAttributes(
		attribute.String("source", source),
		attribute.Bool("value_known", proposalResponse.Data.ExecutionValue != nil),
	)
	if proposalResponse.Data.ExecutionValue == nil {
		span.SetAttributes(attribute.String("execution_value", "unknown"))
	} else {
		span.SetAttributes(attribute.String("execution_value", proposalResponse.Data.ExecutionValue.String()))
	}
	if score := proposalResponse.Data.Value(); score == nil {
		span.SetAttributes(attribute.String("score", "unknown"))
	} else {
		span.SetAttributes(attribute.String("score", score.String()))
	}
	if proposalRoot, err := proposalResponse.Data.Root(); err == nil {
		span.SetAttributes(attribute.String("proposal_root", proposalRoot.String()))
	}
	respCh <- &beaconBlockEPBSResponse{
		provider: name,
		proposal: proposalResponse.Data,
		metadata: proposalResponse.Metadata,
		elapsed:  time.Since(providerStarted),
	}
}

func (s *Service) logEPBSProviderTimeout(slot phase0.Slot,
	requestID string,
	provider string,
	elapsed time.Duration,
	reason string,
) {
	s.log.Info().
		Uint64("slot", uint64(slot)).
		Str("request_id", requestID).
		Str("provider", beaconblockproposer.StableProviderName(provider)).
		Str("proposal_root", "unknown").
		Str("source", "unknown").
		Str("builder_index", "unknown").
		Bool("value_known", false).
		Str("execution_value", "unknown").
		Bool("payload_included", false).
		Bool("builder_url_present", false).
		Dur("latency", elapsed).
		Str("outcome", "timeout").
		Str("rejection_reason", reason).
		Msg("ePBS proposal provider completed")
}

func (s *Service) logEPBSProviderError(slot phase0.Slot, requestID string, providerError *beaconBlockError) {
	s.log.Info().
		Uint64("slot", uint64(slot)).
		Str("request_id", requestID).
		Str("provider", beaconblockproposer.StableProviderName(providerError.provider)).
		Str("proposal_root", "unknown").
		Str("source", "unknown").
		Str("builder_index", "unknown").
		Bool("value_known", false).
		Str("execution_value", "unknown").
		Bool("payload_included", false).
		Bool("builder_url_present", false).
		Dur("latency", providerError.elapsed).
		Str("outcome", providerError.outcome).
		Str("rejection_reason", providerError.rejectionReason).
		Str("error", beaconblockproposer.SafeError(providerError.err, providerError.provider)).
		Msg("ePBS proposal provider completed")
}

func (s *Service) logEPBSProviderResult(slot phase0.Slot,
	requestID string,
	response *beaconBlockEPBSResponse,
	outcome string,
	rejectionReason string,
) {
	builderIndex := uint64(0)
	if signedBid, err := beaconblockproposal.EPBSProposalBid(response.proposal); err == nil {
		builderIndex = uint64(signedBid.Message.BuilderIndex)
	}
	event := s.log.Info().
		Uint64("slot", uint64(slot)).
		Str("request_id", requestID).
		Str("provider", beaconblockproposer.StableProviderName(response.provider)).
		Str("source", beaconblockproposal.EPBSProposalSource(response.proposal, response.metadata)).
		Uint64("builder_index", builderIndex).
		Bool("value_known", response.proposal.ExecutionValue != nil).
		Bool("payload_included", response.proposal.ExecutionPayloadIncluded).
		Bool("builder_url_present", beaconblockproposer.BuilderURLPresent(response.metadata)).
		Dur("latency", response.elapsed).
		Str("outcome", outcome).
		Str("rejection_reason", rejectionReason)
	if response.proposal.ExecutionValue == nil {
		event = event.Str("execution_value", "unknown")
	} else {
		event = event.Str("execution_value", response.proposal.ExecutionValue.String())
	}
	event.Msg("ePBS proposal provider completed")
}

// Proposal provides the best beacon block proposal from a number of beacon nodes.
func (s *Service) Proposal(ctx context.Context,
	opts *api.ProposalOpts,
) (
	*api.Response[*api.VersionedProposal],
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockproposal.best").Start(ctx, "Proposal", trace.WithAttributes(
		attribute.Int64("slot", util.SlotToInt64(opts.Slot)),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, s.log, "strategy_id").With().Uint64("slot", uint64(opts.Slot)).Logger()
	ctx = log.WithContext(ctx)

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
		providerOpts := *opts
		providerGraffiti, err := beaconblockproposal.GraffitiForProvider(ctx, provider, providerOpts.Graffiti)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to obtain node client; not updating graffiti")
		}
		providerOpts.Graffiti = providerGraffiti
		go s.beaconBlockProposal(ctx, started, name, provider, respCh, errCh, &providerOpts)
	}

	results := waitForProposalResponses(ctx, softCtx, softCancel, started, requests, respCh, errCh, log)
	cancel()

	log.Trace().
		Dur("elapsed", time.Since(started)).
		Int("responded", results.responded).
		Int("errored", results.errored).
		Int("timed_out", results.timedOut).
		Msg("Results")

	if results.bestProposal == nil {
		return nil, errors.New("no proposals received")
	}
	log.Trace().Str("provider", results.bestProvider).Stringer("proposal", results.bestProposal).Float64("score", results.bestScore).Dur("elapsed", time.Since(started)).Msg("Selected best proposal")
	if results.bestProvider != "" {
		s.clientMonitor.StrategyOperation("best", results.bestProvider, "beacon block proposal", time.Since(started))
	}

	span.SetAttributes(
		attribute.String("value", new(big.Int).Add(results.bestProposal.ConsensusValue, results.bestProposal.ExecutionValue).String()),
		attribute.Bool("blinded", results.bestProposal.Blinded),
	)
	return &api.Response[*api.VersionedProposal]{
		Data:     results.bestProposal,
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
	log := zerolog.Ctx(ctx).With().Str("provider", name).Logger()

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

	gasLimit, err := proposalResponse.Data.GasLimit()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain proposal gas limit")
	} else {
		log.Trace().Str("provider", name).Uint64("gas_limit", gasLimit).Msg("Proposal gas limit")
	}

	score := s.scoreBeaconBlockProposal(ctx, name, proposal)
	span.SetAttributes(attribute.Float64("score", score))
	respCh <- &beaconBlockResponse{
		provider: name,
		proposal: proposal,
		score:    score,
	}
}
