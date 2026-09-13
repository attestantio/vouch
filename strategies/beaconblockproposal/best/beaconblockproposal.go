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
	"bytes"
	"context"
	"math"
	"math/big"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
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

// epbsSelection carries the state of one round of ePBS proposal selection across the
// soft-deadline and hard-deadline collection phases.
type epbsSelection struct {
	provider string
	opts     *api.EPBSProposalOpts

	requestID string
	started   time.Time
	requests  int
	pending   map[string]struct{}
	proposal  *api.VersionedEPBSProposal
	metadata  map[string]any

	responded    int
	errored      int
	timedOut     int
	softTimedOut int

	softDeadlineReached bool
	hardDeadlineReached bool

	respCh chan *beaconBlockEPBSResponse
	errCh  chan *beaconBlockError
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
	selection := &epbsSelection{
		opts:      opts,
		requestID: requestID,
		started:   started,
		requests:  requests,
		respCh:    make(chan *beaconBlockEPBSResponse, requests),
		errCh:     make(chan *beaconBlockError, requests),
		pending:   make(map[string]struct{}, requests),
	}
	for name, provider := range s.proposalProviders {
		selection.pending[name] = struct{}{}
		providerOpts := *opts
		go s.epbsProposal(ctx, started, name, provider, selection.respCh, selection.errCh, &providerOpts, log)
	}

	s.gatherEPBSProposals(ctx, softCtx, softCancel, selection, log)

	selection.hardDeadlineReached = selection.hardDeadlineReached || errors.Is(ctx.Err(), context.DeadlineExceeded)
	if selection.proposal == nil {
		logEPBSSelectionFailed(selection, log)
		return nil, errors.New("no ePBS proposals received")
	}

	valueKnown := selection.proposal.Value() != nil
	source := epbsProposalSource(selection.proposal, selection.metadata)
	stableBestProvider := beaconblockproposer.StableProviderName(selection.provider)
	proposalRootString := epbsProposalRootString(selection.proposal)
	span.SetAttributes(
		attribute.String("proposal_root", proposalRootString),
		attribute.String("provider", stableBestProvider),
		attribute.String("source", source),
		attribute.Bool("value_known", valueKnown),
		attribute.Bool("fallback", !valueKnown),
		attribute.Bool("soft_deadline_reached", selection.softDeadlineReached),
		attribute.Bool("hard_deadline_reached", selection.hardDeadlineReached),
	)
	if selection.provider != "" {
		s.clientMonitor.StrategyOperation("best", selection.provider, "ePBS beacon block proposal", time.Since(started))
	}

	log.Info().
		Uint64("slot", uint64(opts.Slot)).
		Str("request_id", requestID).
		Str("provider", stableBestProvider).
		Str("proposal_root", proposalRootString).
		Str("source", source).
		Dur("elapsed", time.Since(started)).
		Int("responded", selection.responded).
		Int("errored", selection.errored).
		Int("timed_out", selection.timedOut).
		Bool("value_known", valueKnown).
		Bool("fallback", !valueKnown).
		Bool("deadline_reached", selection.hardDeadlineReached).
		Bool("soft_deadline_reached", selection.softDeadlineReached).
		Bool("hard_deadline_reached", selection.hardDeadlineReached).
		Str("outcome", "selected").
		Msg("ePBS proposal selection completed")

	metadata := make(map[string]any, 4)
	metadata[beaconblockproposer.MetadataStrategy] = "best"
	metadata[beaconblockproposer.MetadataProvider] = stableBestProvider
	metadata[beaconblockproposer.MetadataSource] = source
	metadata[beaconblockproposer.MetadataFallback] = !valueKnown
	return &api.Response[*api.VersionedEPBSProposal]{
		Data:     selection.proposal,
		Metadata: metadata,
	}, nil
}

// gatherEPBSProposals collects provider responses in two phases: until the soft deadline, after
// which a best proposal already in hand stands in for the stragglers, and then until the hard
// deadline for the case where nothing has arrived yet.
func (s *Service) gatherEPBSProposals(ctx context.Context,
	softCtx context.Context,
	softCancel context.CancelFunc,
	selection *epbsSelection,
	log zerolog.Logger,
) {
	for selection.responded+selection.errored+selection.timedOut+selection.softTimedOut != selection.requests {
		select {
		case response := <-selection.respCh:
			s.considerEPBSResponse(selection, response, log)
		case err := <-selection.errCh:
			s.recordEPBSError(selection, err)
		case <-softCtx.Done():
			s.handleEPBSSoftDeadline(selection, log)
		}
	}
	softCancel()

	for selection.responded+selection.errored+selection.timedOut != selection.requests {
		select {
		case response := <-selection.respCh:
			s.considerEPBSResponse(selection, response, log)
		case err := <-selection.errCh:
			s.recordEPBSError(selection, err)
		case <-ctx.Done():
			selection.hardDeadlineReached = true
			selection.timedOut = selection.requests - selection.responded - selection.errored
			s.timeOutPendingEPBSProviders(selection, "deadline_reached")
		}
	}
}

// considerEPBSResponse folds a provider response into the running best proposal.
func (s *Service) considerEPBSResponse(selection *epbsSelection,
	response *beaconBlockEPBSResponse,
	log zerolog.Logger,
) {
	selection.responded++
	delete(selection.pending, response.provider)
	previousBest := selection.proposal
	selection.proposal, selection.provider = s.considerEPBSProposal(selection.opts, response, selection.proposal, selection.provider, log)
	if selection.proposal != previousBest {
		// This response displaced the incumbent, so its metadata describes the new best.
		selection.metadata = response.metadata
	}
	outcome := "accepted"
	if response.rejectionReason != "" {
		outcome = "rejected"
	}
	s.logEPBSProviderResult(selection.opts.Slot, selection.requestID, response, outcome, response.rejectionReason)
}

// recordEPBSError notes that a provider failed to supply a proposal.
func (s *Service) recordEPBSError(selection *epbsSelection, providerError *beaconBlockError) {
	selection.errored++
	delete(selection.pending, providerError.provider)
	s.logEPBSProviderError(selection.opts.Slot, selection.requestID, providerError)
}

// handleEPBSSoftDeadline stops waiting on providers that have not responded by the soft deadline,
// but only counts them out once a usable proposal is already in hand.
func (s *Service) handleEPBSSoftDeadline(selection *epbsSelection, log zerolog.Logger) {
	selection.softDeadlineReached = true
	if selection.proposal != nil {
		selection.timedOut = selection.requests - selection.responded - selection.errored
		s.timeOutPendingEPBSProviders(selection, "soft_deadline_reached")
		log.Debug().
			Dur("elapsed", time.Since(selection.started)).
			Int("responded", selection.responded).
			Int("errored", selection.errored).
			Int("timed_out", selection.timedOut).
			Msg("Soft timeout reached with responses")
	} else {
		log.Debug().
			Dur("elapsed", time.Since(selection.started)).
			Int("errored", selection.errored).
			Msg("Soft timeout reached with no valid responses")
	}
	selection.softTimedOut = selection.requests - selection.responded - selection.errored - selection.timedOut
}

// timeOutPendingEPBSProviders logs and clears every provider still outstanding.
func (s *Service) timeOutPendingEPBSProviders(selection *epbsSelection, reason string) {
	for provider := range selection.pending {
		s.logEPBSProviderTimeout(selection.opts.Slot, selection.requestID, provider, time.Since(selection.started), reason)
		delete(selection.pending, provider)
	}
}

// logEPBSSelectionFailed reports a round that produced no usable proposal.
func logEPBSSelectionFailed(selection *epbsSelection, log zerolog.Logger) {
	outcome := "no_valid_proposal"
	if selection.hardDeadlineReached {
		outcome = "timeout"
	}
	log.Info().
		Uint64("slot", uint64(selection.opts.Slot)).
		Str("request_id", selection.requestID).
		Str("provider", "unknown").
		Str("proposal_root", "unknown").
		Dur("elapsed", time.Since(selection.started)).
		Int("responded", selection.responded).
		Int("errored", selection.errored).
		Int("timed_out", selection.timedOut).
		Bool("deadline_reached", selection.hardDeadlineReached).
		Bool("soft_deadline_reached", selection.softDeadlineReached).
		Bool("hard_deadline_reached", selection.hardDeadlineReached).
		Str("outcome", outcome).
		Msg("ePBS proposal selection completed")
}

// epbsProposalRootString renders a proposal's root for telemetry, or "unknown" if unavailable.
func epbsProposalRootString(proposal *api.VersionedEPBSProposal) string {
	proposalRoot, err := proposal.Root()
	if err != nil {
		return "unknown"
	}

	return proposalRoot.String()
}

// considerEPBSProposal updates the best proposal seen so far, ignoring proposals that are
// inconsistent with the auction result their bid reports.
func (s *Service) considerEPBSProposal(opts *api.EPBSProposalOpts,
	response *beaconBlockEPBSResponse,
	bestProposal *api.VersionedEPBSProposal,
	bestProvider string,
	log zerolog.Logger,
) (*api.VersionedEPBSProposal, string) {
	// validateEPBSProposal has already rejected a Gloas proposal without a bid, so a nil block
	// here means the proposal predates Gloas and is self-built by definition.
	builderBacked := false
	if block := epbsProposalBlock(response.proposal); block != nil {
		bid := block.Body.SignedExecutionPayloadBid.Message
		builderBacked = bid.BuilderIndex != selfBuiltBuilderIndex
		if builderBacked && s.providerReadiness != nil && !s.providerReadiness.ProviderReady(response.provider, opts.Slot, block.ProposerIndex) {
			log.Warn().Str("provider", beaconblockproposer.StableProviderName(response.provider)).Msg("Discarding builder-backed ePBS proposal from provider without current preferences")
			response.rejectionReason = "provider_preferences_not_ready"

			return bestProposal, bestProvider
		}
	}
	// The beacon node cannot return a builder's payload, so only a self-built proposal can
	// carry the payload that was requested.
	if builderBacked {
		if response.proposal.ExecutionPayloadIncluded {
			log.Warn().Str("provider", beaconblockproposer.StableProviderName(response.provider)).Msg("Discarding builder-backed ePBS proposal carrying an execution payload")
			response.rejectionReason = "builder_payload_included"

			return bestProposal, bestProvider
		}
	} else if opts.IncludePayload != nil && *opts.IncludePayload && !response.proposal.ExecutionPayloadIncluded {
		log.Warn().Str("provider", beaconblockproposer.StableProviderName(response.provider)).Msg("Discarding ePBS proposal without requested execution payload")
		response.rejectionReason = "requested_payload_missing"

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
	provider beaconblockproposer.ProposalDataProvider,
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

	providerGraffiti := opts.Graffiti[:]
	if bytes.Contains(providerGraffiti, []byte("{{CLIENT}}")) {
		if nodeClientProvider, isProvider := provider.(eth2client.NodeClientProvider); isProvider {
			nodeClientResponse, err := nodeClientProvider.NodeClient(ctx)
			if err != nil {
				log.Warn().Str("error", beaconblockproposer.SafeError(err, name)).Msg("Failed to obtain node client; not updating graffiti")
			} else {
				providerGraffiti = bytes.ReplaceAll(providerGraffiti, []byte("{{CLIENT}}"), []byte(nodeClientResponse.Data))
			}
			if len(providerGraffiti) > 32 {
				providerGraffiti = providerGraffiti[0:32]
			}
			var graffiti [32]byte
			copy(graffiti[:], providerGraffiti)
			opts.Graffiti = graffiti
		}
	}

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

	if err := validateEPBSProposal(proposalResponse.Data); err != nil {
		errCh <- &beaconBlockError{
			provider:        name,
			err:             err,
			elapsed:         time.Since(providerStarted),
			outcome:         "rejected",
			rejectionReason: "invalid_proposal",
		}

		return
	}

	source := epbsProposalSource(proposalResponse.Data, proposalResponse.Metadata)
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
	block := epbsProposalBlock(response.proposal)
	builderIndex := uint64(0)
	if block != nil {
		builderIndex = uint64(block.Body.SignedExecutionPayloadBid.Message.BuilderIndex)
	}
	event := s.log.Info().
		Uint64("slot", uint64(slot)).
		Str("request_id", requestID).
		Str("provider", beaconblockproposer.StableProviderName(response.provider)).
		Str("source", epbsProposalSource(response.proposal, response.metadata)).
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

func epbsProposalSource(proposal *api.VersionedEPBSProposal, metadata map[string]any) string {
	// A proposal from before Gloas carries no bid, so there was no auction and the beacon node
	// built it itself.  validateEPBSProposal has already rejected a Gloas proposal with no bid,
	// so a nil block here can only be that pre-Gloas case.
	block := epbsProposalBlock(proposal)
	if block == nil || block.Body.SignedExecutionPayloadBid.Message.BuilderIndex == selfBuiltBuilderIndex {
		return "self_build"
	}
	if beaconblockproposer.BuilderURLPresent(metadata) {
		return "builder_api"
	}
	return "p2p_builder"
}

// validateEPBSProposal confirms that an ePBS proposal is structurally sound and pays a fee recipient.
// The caller must have already excluded a nil proposal.
func validateEPBSProposal(proposal *api.VersionedEPBSProposal) error {
	if proposal.Version != spec.DataVersionGloas {
		return nil
	}

	block := epbsProposalBlock(proposal)
	if block == nil {
		return errors.New("beacon node returned malformed ePBS proposal")
	}

	if block.Body.SignedExecutionPayloadBid.Message.FeeRecipient.IsZero() {
		return errors.New("beacon block obtained with 0 fee recipient")
	}

	return nil
}

// selfBuiltBuilderIndex is the builder index a beacon node sets on a bid for its own build.
const selfBuiltBuilderIndex = gloas.BuilderIndex(math.MaxUint64)

// epbsProposalBlock returns the Gloas block of a proposal, or nil if the proposal does not carry
// one with an execution payload bid.
func epbsProposalBlock(proposal *api.VersionedEPBSProposal) *gloas.BeaconBlock {
	if proposal.Version != spec.DataVersionGloas {
		return nil
	}
	block := proposal.Gloas
	if proposal.ExecutionPayloadIncluded {
		if proposal.GloasContents == nil {
			return nil
		}
		block = proposal.GloasContents.Block
	}
	if block == nil || block.Body == nil || block.Body.SignedExecutionPayloadBid == nil || block.Body.SignedExecutionPayloadBid.Message == nil {
		return nil
	}

	return block
}

// Proposal provides the best beacon block proposal from a number of beacon nodes.
// Complexity is due to the soft and hard timeout response loops, each of which handles a
// response, an error and a timeout from every beacon node.
// skipcq: GO-R1005
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
	results := s.collectBeaconBlockProposalResponses(log.WithContext(ctx), started, opts, log)
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

type beaconBlockProposalResults struct {
	bestProvider string
	bestProposal *api.VersionedProposal
	requests     int
	responded    int
	errored      int
	timedOut     int
	softTimedOut int
	bestScore    float64
}

func (s *Service) collectBeaconBlockProposalResponses(ctx context.Context,
	started time.Time,
	opts *api.ProposalOpts,
	log zerolog.Logger,
) *beaconBlockProposalResults {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)
	defer softCancel()

	results := &beaconBlockProposalResults{requests: len(s.proposalProviders)}
	respCh, errCh := s.startBeaconBlockProposalRequests(ctx, started, opts, log, results.requests)
	for results.responded+results.errored+results.timedOut+results.softTimedOut != results.requests {
		select {
		case response := <-respCh:
			results.selectProposal(response, started, log)
		case responseErr := <-errCh:
			results.recordError(responseErr, started, log)
		case <-softCtx.Done():
			results.softTimeout(started, log)
		}
	}
	softCancel()

	for results.responded+results.errored+results.timedOut != results.requests {
		select {
		case response := <-respCh:
			results.selectProposal(response, started, log)
		case responseErr := <-errCh:
			results.recordError(responseErr, started, log)
		case <-ctx.Done():
			results.hardTimeout(started, log)
		}
	}
	cancel()

	log.Trace().
		Dur("elapsed", time.Since(started)).
		Int("responded", results.responded).
		Int("errored", results.errored).
		Int("timed_out", results.timedOut).
		Msg("Results")

	return results
}

func (s *Service) startBeaconBlockProposalRequests(ctx context.Context,
	started time.Time,
	opts *api.ProposalOpts,
	log zerolog.Logger,
	requests int,
) (chan *beaconBlockResponse, chan *beaconBlockError) {
	respCh := make(chan *beaconBlockResponse, requests)
	errCh := make(chan *beaconBlockError, requests)
	for name, provider := range s.proposalProviders {
		providerOpts := *opts
		providerGraffiti := providerOpts.Graffiti[:]
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
				var graffiti [32]byte
				copy(graffiti[:], providerGraffiti)
				providerOpts.Graffiti = graffiti
			}
		}
		go s.beaconBlockProposal(ctx, started, name, provider, respCh, errCh, &providerOpts)
	}

	return respCh, errCh
}

func (r *beaconBlockProposalResults) selectProposal(response *beaconBlockResponse, started time.Time, log zerolog.Logger) {
	r.responded++
	log.Trace().
		Dur("elapsed", time.Since(started)).
		Str("provider", response.provider).
		Int("responded", r.responded).
		Int("errored", r.errored).
		Int("timed_out", r.timedOut).
		Msg("Response received")
	if r.bestProposal == nil || response.score > r.bestScore {
		r.bestProposal = response.proposal
		r.bestScore = response.score
		r.bestProvider = response.provider
	}
}

func (r *beaconBlockProposalResults) recordError(responseErr *beaconBlockError, started time.Time, log zerolog.Logger) {
	r.errored++
	log.Debug().
		Dur("elapsed", time.Since(started)).
		Str("provider", responseErr.provider).
		Int("responded", r.responded).
		Int("errored", r.errored).
		Int("timed_out", r.timedOut).
		Err(responseErr.err).
		Msg("Error received")
}

func (r *beaconBlockProposalResults) softTimeout(started time.Time, log zerolog.Logger) {
	if r.responded > 0 {
		r.timedOut = r.requests - r.responded - r.errored
		log.Debug().
			Dur("elapsed", time.Since(started)).
			Int("responded", r.responded).
			Int("errored", r.errored).
			Int("timed_out", r.timedOut).
			Msg("Soft timeout reached with responses")
	} else {
		log.Debug().
			Dur("elapsed", time.Since(started)).
			Int("errored", r.errored).
			Msg("Soft timeout reached with no responses")
	}
	r.softTimedOut = r.requests - r.responded - r.errored - r.timedOut
}

func (r *beaconBlockProposalResults) hardTimeout(started time.Time, log zerolog.Logger) {
	r.timedOut = r.requests - r.responded - r.errored
	log.Debug().
		Dur("elapsed", time.Since(started)).
		Int("responded", r.responded).
		Int("errored", r.errored).
		Int("timed_out", r.timedOut).
		Msg("Hard timeout reached")
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
