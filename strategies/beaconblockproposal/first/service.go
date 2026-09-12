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

package first

import (
	"context"
	"math"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/proposerpreferences"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Service is the provider for beacon block proposals.
type Service struct {
	log               zerolog.Logger
	clientMonitor     metrics.ClientMonitor
	proposalProviders map[string]beaconblockproposer.ProposalDataProvider
	providerReadiness proposerpreferences.ProviderReadiness
	timeout           time.Duration
}

// EPBSProposal provides the first ePBS proposal from a number of beacon nodes.
func (s *Service) EPBSProposal(ctx context.Context,
	opts *api.EPBSProposalOpts,
) (
	*api.Response[*api.VersionedEPBSProposal],
	error,
) {
	ctx, requestID := beaconblockproposer.EnsureRequestID(ctx)
	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockproposal.first").Start(ctx, "EPBSProposal", trace.WithAttributes(
		attribute.Int64("slot", util.SlotToInt64(opts.Slot)),
		attribute.String("request_id", requestID),
		attribute.String("provider", "unknown"),
		attribute.String("proposal_root", "unknown"),
		attribute.String("source", "unknown"),
	))
	defer span.End()
	started := time.Now()

	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	proposalCh := make(chan *epbsProposalResponse, len(s.proposalProviders))
	for name, provider := range s.proposalProviders {
		go s.fetchEPBSProposal(ctx, name, provider, opts, proposalCh)
	}

	completed := 0
	for {
		select {
		case <-ctx.Done():
			cancel()
			outcome := "timeout"
			if completed == len(s.proposalProviders) {
				outcome = "no_valid_proposal"
			}
			s.log.Info().
				Uint64("slot", uint64(opts.Slot)).
				Str("request_id", requestID).
				Str("provider", "unknown").
				Str("proposal_root", "unknown").
				Dur("elapsed", time.Since(started)).
				Int("completed", completed).
				Int("providers", len(s.proposalProviders)).
				Str("outcome", outcome).
				Bool("deadline_reached", true).
				Msg("ePBS proposal selection completed")
			return nil, errors.New("failed to obtain ePBS beacon block proposal before timeout")
		case response := <-proposalCh:
			completed++
			if response.logged {
				continue
			}
			if response.err != nil {
				s.logEPBSProviderFailure(opts.Slot, requestID, response, "error", "provider_error")
				continue
			}
			acceptable, rejectionReason := s.acceptableEPBSProposal(response.provider, response.proposal, opts)
			if !acceptable {
				if response.proposal == nil || rejectionReason == "malformed_proposal" {
					s.logEPBSProviderFailure(opts.Slot, requestID, response, "rejected", rejectionReason)
				} else {
					s.logEPBSProviderResult(opts.Slot, requestID, response, "rejected", rejectionReason)
				}
				continue
			}
			s.logEPBSProviderResult(opts.Slot, requestID, response, "accepted", "")
			cancel()

			source := epbsProposalSource(response.proposal, response.metadata)
			valueKnown := response.proposal.Value() != nil
			stableProvider := beaconblockproposer.StableProviderName(response.provider)
			if proposalRoot, err := response.proposal.Root(); err == nil {
				span.SetAttributes(attribute.String("proposal_root", proposalRoot.String()))
			}
			span.SetAttributes(
				attribute.String("provider", stableProvider),
				attribute.String("source", source),
				attribute.Bool("value_known", valueKnown),
				attribute.Bool("fallback", false),
			)
			metadata := make(map[string]any, 4)
			metadata[beaconblockproposer.MetadataStrategy] = s.strategyName()
			metadata[beaconblockproposer.MetadataProvider] = stableProvider
			metadata[beaconblockproposer.MetadataSource] = source
			metadata[beaconblockproposer.MetadataFallback] = false
			return &api.Response[*api.VersionedEPBSProposal]{
				Data:     response.proposal,
				Metadata: metadata,
			}, nil
		}
	}
}

func (s *Service) strategyName() string {
	if len(s.proposalProviders) == 1 {
		if _, exists := s.proposalProviders["simple"]; exists {
			return "simple"
		}
	}
	return "first"
}

// fetchEPBSProposal obtains an ePBS beacon block proposal from a single provider, recording the
// operation with the client monitor, and sends the result to ch unless ctx is done first.
func (s *Service) fetchEPBSProposal(ctx context.Context,
	name string,
	provider beaconblockproposer.ProposalDataProvider,
	opts *api.EPBSProposalOpts,
	ch chan *epbsProposalResponse,
) {
	stableProvider := beaconblockproposer.StableProviderName(name)
	log := s.log.With().Str("provider", stableProvider).Uint64("slot", uint64(opts.Slot)).Logger()

	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockproposal.first").Start(ctx, "ePBSBeaconBlockProposal", trace.WithAttributes(
		attribute.Int64("slot", util.SlotToInt64(opts.Slot)),
		attribute.String("request_id", beaconblockproposer.RequestID(ctx)),
		attribute.String("provider", stableProvider),
		attribute.String("proposal_root", "unknown"),
		attribute.String("source", "unknown"),
	))
	defer span.End()

	started := time.Now()
	proposalResponse, err := provider.EPBSProposal(ctx, opts)
	s.clientMonitor.ClientOperation(name, "ePBS beacon block proposal", err == nil, time.Since(started))
	if err != nil {
		if errors.Is(err, context.Canceled) {
			s.logEPBSProviderFailure(opts.Slot, beaconblockproposer.RequestID(ctx), &epbsProposalResponse{
				provider: name,
				err:      err,
				elapsed:  time.Since(started),
			}, "cancelled", "selection_completed")
			return
		}
		response := &epbsProposalResponse{provider: name, err: err, elapsed: time.Since(started), logged: true}
		outcome := "error"
		rejectionReason := "provider_error"
		if errors.Is(err, context.DeadlineExceeded) {
			outcome = "timeout"
			rejectionReason = "deadline_reached"
		}
		s.logEPBSProviderFailure(opts.Slot, beaconblockproposer.RequestID(ctx), response, outcome, rejectionReason)
		ch <- response

		return
	}
	if proposalResponse == nil {
		response := &epbsProposalResponse{provider: name, elapsed: time.Since(started), logged: true}
		outcome := "rejected"
		rejectionReason := "empty_response"
		if ctx.Err() != nil {
			outcome = "cancelled"
			rejectionReason = "selection_completed"
		}
		s.logEPBSProviderFailure(opts.Slot, beaconblockproposer.RequestID(ctx), response, outcome, rejectionReason)
		ch <- response

		return
	}
	proposal := proposalResponse.Data
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained ePBS beacon block proposal")
	metadata := proposalResponse.Metadata
	if proposal != nil {
		source := epbsProposalSource(proposal, metadata)
		span.SetAttributes(attribute.String("source", source))
		if proposalRoot, err := proposal.Root(); err == nil {
			span.SetAttributes(attribute.String("proposal_root", proposalRoot.String()))
		}
	}
	response := &epbsProposalResponse{provider: name, proposal: proposal, metadata: metadata, elapsed: time.Since(started)}
	if ctx.Err() != nil {
		s.logCancelledEPBSProvider(opts.Slot, beaconblockproposer.RequestID(ctx), response)
		return
	}

	select {
	case ch <- response:
	case <-ctx.Done():
		s.logCancelledEPBSProvider(opts.Slot, beaconblockproposer.RequestID(ctx), response)
	}
}

type epbsProposalResponse struct {
	provider string
	proposal *api.VersionedEPBSProposal
	metadata map[string]any
	err      error
	elapsed  time.Duration
	logged   bool
}

func (s *Service) logCancelledEPBSProvider(slot phase0.Slot, requestID string, response *epbsProposalResponse) {
	if response.proposal == nil {
		s.logEPBSProviderFailure(slot, requestID, response, "cancelled", "selection_completed")
		return
	}
	s.logEPBSProviderResult(slot, requestID, response, "cancelled", "selection_completed")
}

func (s *Service) logEPBSProviderFailure(slot phase0.Slot,
	requestID string,
	response *epbsProposalResponse,
	outcome string,
	rejectionReason string,
) {
	event := s.log.Info().
		Uint64("slot", uint64(slot)).
		Str("request_id", requestID).
		Str("provider", beaconblockproposer.StableProviderName(response.provider)).
		Str("proposal_root", "unknown").
		Str("source", "unknown").
		Str("builder_index", "unknown").
		Bool("value_known", false).
		Str("execution_value", "unknown").
		Bool("payload_included", false).
		Bool("builder_url_present", false).
		Dur("latency", response.elapsed).
		Str("outcome", outcome).
		Str("rejection_reason", rejectionReason)
	if response.err != nil {
		event = event.Str("error", beaconblockproposer.SafeError(response.err, response.provider))
	}
	event.Msg("ePBS proposal provider completed")
}

func (s *Service) logEPBSProviderResult(slot phase0.Slot,
	requestID string,
	response *epbsProposalResponse,
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
	block := epbsProposalBlock(proposal)
	if block != nil && block.Body.SignedExecutionPayloadBid.Message.BuilderIndex == selfBuiltBuilderIndex {
		return "self_build"
	}
	if beaconblockproposer.BuilderURLPresent(metadata) {
		return "builder_api"
	}
	return "p2p_builder"
}

// acceptableEPBSProposal reports whether proposal is usable, discarding and logging it if it is
// nil, is inconsistent with the auction result its bid reports, comes from an unready builder
// provider, or (for Gloas) is structurally malformed or pays a zero fee recipient.
func (s *Service) acceptableEPBSProposal(provider string,
	proposal *api.VersionedEPBSProposal,
	opts *api.EPBSProposalOpts,
) (bool, string) {
	if proposal == nil {
		s.log.Warn().Msg("Discarding empty ePBS proposal")

		return false, "empty_response"
	}
	builderBacked, acceptable, rejectionReason := s.acceptableEPBSBid(provider, proposal, opts)
	if !acceptable {
		return false, rejectionReason
	}
	if builderBacked {
		if proposal.ExecutionPayloadIncluded {
			s.log.Warn().Msg("Discarding builder-backed ePBS proposal carrying an execution payload")

			return false, "builder_payload_included"
		}

		return true, ""
	}
	if opts.IncludePayload != nil && *opts.IncludePayload && !proposal.ExecutionPayloadIncluded {
		s.log.Warn().Msg("Discarding ePBS proposal without requested execution payload")

		return false, "requested_payload_missing"
	}

	return true, ""
}

// acceptableEPBSBid reports whether the auction result a Gloas proposal's bid carries is
// builder-backed, and whether the bid is usable at all. A proposal from before Gloas carries no
// bid, so it is self-built and acceptable by default.
func (s *Service) acceptableEPBSBid(provider string,
	proposal *api.VersionedEPBSProposal,
	opts *api.EPBSProposalOpts,
) (
	bool,
	bool,
	string,
) {
	if proposal.Version != spec.DataVersionGloas {
		return false, true, ""
	}
	block := epbsProposalBlock(proposal)
	if block == nil {
		s.log.Warn().Msg("Discarding malformed ePBS proposal")

		return false, false, "malformed_proposal"
	}
	bid := block.Body.SignedExecutionPayloadBid.Message
	builderBacked := bid.BuilderIndex != selfBuiltBuilderIndex
	if builderBacked && s.providerReadiness != nil && !s.providerReadiness.ProviderReady(provider, opts.Slot, block.ProposerIndex) {
		s.log.Warn().Str("provider", beaconblockproposer.StableProviderName(provider)).Msg("Discarding builder-backed ePBS proposal from provider without current preferences")

		return false, false, "provider_preferences_not_ready"
	}
	if bid.FeeRecipient.IsZero() {
		s.log.Warn().Msg("Discarding ePBS proposal with 0 fee recipient")

		return false, false, "zero_fee_recipient"
	}

	return builderBacked, true, ""
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

// New creates a new beacon block proposal strategy.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("strategy", "beaconblockproposal").Str("impl", "first").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		log:               log,
		proposalProviders: parameters.proposalProviders,
		providerReadiness: parameters.providerReadiness,
		timeout:           parameters.timeout,
		clientMonitor:     parameters.clientMonitor,
	}

	return s, nil
}

// Proposal provides the first beacon block proposal from a number of beacon nodes.
func (s *Service) Proposal(ctx context.Context,
	opts *api.ProposalOpts,
) (
	*api.Response[*api.VersionedProposal],
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockproposal.first").Start(ctx, "Proposal", trace.WithAttributes(
		attribute.Int64("slot", util.SlotToInt64(opts.Slot)),
	))
	defer span.End()

	// We create a cancelable context with a timeout.  As soon as the first provider has responded we
	// cancel the context to cancel the other requests.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	proposalCh := make(chan *api.VersionedProposal, 1)
	for name, provider := range s.proposalProviders {
		go func(ctx context.Context, name string, provider eth2client.ProposalProvider, ch chan *api.VersionedProposal) {
			log := s.log.With().Str("provider", name).Uint64("slot", uint64(opts.Slot)).Logger()

			started := time.Now()
			proposalResponse, err := provider.Proposal(ctx, opts)
			s.clientMonitor.ClientOperation(name, "beacon block proposal", err == nil, time.Since(started))
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					log.Debug().Err(err).Msg("Failed to obtain beacon block proposal")
				}

				return
			}
			proposal := proposalResponse.Data
			log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained beacon block proposal")

			ch <- proposal
		}(ctx, name, provider, proposalCh)
	}

	select {
	case <-ctx.Done():
		cancel()
		s.log.Debug().Msg("Failed to obtain beacon block proposal before timeout")
		return nil, errors.New("failed to obtain beacon block proposal before timeout")
	case proposal := <-proposalCh:
		cancel()
		return &api.Response[*api.VersionedProposal]{
			Data:     proposal,
			Metadata: make(map[string]any),
		}, nil
	}
}
