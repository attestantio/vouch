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
	stderrors "errors"
	"fmt"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/proposerpreferences"
	"github.com/attestantio/vouch/strategies/beaconblockproposal"
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
	proposalProviders map[string]eth2client.MultiForkProposalProvider
	providerReadiness proposerpreferences.ProviderReadiness
	timeout           time.Duration
}

type proposalResult[T any] struct {
	provider string
	proposal T
	err      error
}

func proposalResults[P any, T any](providers map[string]P,
	request func(string, P) *proposalResult[T],
) <-chan *proposalResult[T] {
	results := make(chan *proposalResult[T], len(providers))
	for name, provider := range providers {
		go func(name string, provider P) {
			results <- request(name, provider)
		}(name, provider)
	}

	return results
}

func fetchProviderProposal[R any, T any](s *Service,
	log zerolog.Logger,
	name string,
	operation string,
	request func() (*api.Response[R], error),
	proposal func(*api.Response[R]) (T, error),
) *proposalResult[T] {
	result := &proposalResult[T]{provider: name}
	started := time.Now()
	response, err := request()
	s.clientMonitor.ClientOperation(name, operation, err == nil, time.Since(started))
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Debug().Err(err).Msg("Failed to obtain " + operation)
		}
		result.err = err

		return result
	}

	result.proposal, result.err = proposal(response)
	if result.err == nil {
		log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained " + operation)
	}

	return result
}

func firstProposal[T any](ctx context.Context,
	log zerolog.Logger,
	results <-chan *proposalResult[T],
	providers int,
	validate func(string, T) error,
	failure string,
	timeoutMessage string,
) (
	T,
	error,
) {
	var zero T
	proposalErrors := make([]error, 0, providers)
	processResult := func(result *proposalResult[T]) (T, bool) {
		if result.err != nil {
			proposalErrors = append(proposalErrors, fmt.Errorf("%s: %w", result.provider, result.err))

			return zero, false
		}
		if validate != nil {
			if err := validate(result.provider, result.proposal); err != nil {
				proposalErrors = append(proposalErrors, fmt.Errorf("%s: %w", result.provider, err))

				return zero, false
			}
		}

		return result.proposal, true
	}

	completed := 0
	for completed < providers {
		select {
		case result := <-results:
			completed++
			if proposal, valid := processResult(result); valid {
				return proposal, nil
			}
		case <-ctx.Done():
			log.Debug().Msg(timeoutMessage)
			for {
				select {
				case result := <-results:
					completed++
					if proposal, valid := processResult(result); valid {
						return proposal, nil
					}
				default:
					if completed < providers {
						proposalErrors = append(proposalErrors, ctx.Err())
					}

					return zero, errors.Wrap(stderrors.Join(proposalErrors...), failure)
				}
			}
		}
	}

	return zero, errors.Wrap(stderrors.Join(proposalErrors...), failure)
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
	defer cancel()

	results := proposalResults(s.proposalProviders, func(name string,
		provider eth2client.MultiForkProposalProvider,
	) *proposalResult[*epbsProposalResponse] {
		return s.fetchEPBSProposal(ctx, name, provider, opts)
	})

	response, err := firstProposal(ctx,
		s.log,
		results,
		len(s.proposalProviders),
		func(provider string, response *epbsProposalResponse) error {
			return s.validateEPBSProposal(requestID, provider, response, opts)
		},
		"failed to obtain ePBS beacon block proposal",
		"Failed to obtain ePBS beacon block proposal before timeout",
	)
	if err != nil {
		outcome := "no_valid_proposal"
		deadlineReached := errors.Is(ctx.Err(), context.DeadlineExceeded)
		if deadlineReached {
			outcome = "timeout"
		}
		s.log.Info().
			Uint64("slot", uint64(opts.Slot)).
			Str("request_id", requestID).
			Str("provider", "unknown").
			Str("proposal_root", "unknown").
			Dur("elapsed", time.Since(started)).
			Int("providers", len(s.proposalProviders)).
			Str("outcome", outcome).
			Bool("deadline_reached", deadlineReached).
			Msg("ePBS proposal selection completed")

		return nil, err
	}

	source := beaconblockproposal.EPBSProposalSource(response.proposal, response.metadata)
	valueKnown := response.proposal.Value() != nil
	stableProvider := beaconblockproposer.StableProviderName(response.provider)
	proposalRootString := "unknown"
	if proposalRoot, err := response.proposal.Root(); err == nil {
		proposalRootString = proposalRoot.String()
	}
	span.SetAttributes(
		attribute.String("proposal_root", proposalRootString),
		attribute.String("provider", stableProvider),
		attribute.String("source", source),
		attribute.Bool("value_known", valueKnown),
		attribute.Bool("fallback", false),
	)
	span.SetAttributes(beaconblockproposer.ClientDetailsAttributes(response.provider)...)
	selectionEvent := s.log.Info().
		Uint64("slot", uint64(opts.Slot)).
		Str("request_id", requestID).
		Str("provider", stableProvider).
		Str("proposal_root", proposalRootString).
		Str("source", source).
		Dur("elapsed", time.Since(started)).
		Int("providers", len(s.proposalProviders)).
		Bool("value_known", valueKnown).
		Bool("fallback", false).
		Str("outcome", "selected").
		Bool("deadline_reached", false)
	beaconblockproposer.WithClientDetails(selectionEvent, response.provider)
	selectionEvent.Msg("ePBS proposal selection completed")
	metadata := make(map[string]any, 4)
	metadata[beaconblockproposer.MetadataStrategy] = "first"
	metadata[beaconblockproposer.MetadataProvider] = stableProvider
	metadata[beaconblockproposer.MetadataSource] = source
	metadata[beaconblockproposer.MetadataFallback] = false

	return &api.Response[*api.VersionedEPBSProposal]{
		Data:     response.proposal,
		Metadata: metadata,
	}, nil
}

var errNoEPBSProposalResponse = errors.New("beacon node returned no ePBS proposal response")

type epbsProposalResponse struct {
	provider string
	proposal *api.VersionedEPBSProposal
	metadata map[string]any
	elapsed  time.Duration
}

// fetchEPBSProposal obtains an ePBS proposal from a single provider, logging a provider that
// fails or that completes after selection has finished.
func (s *Service) fetchEPBSProposal(ctx context.Context,
	name string,
	provider eth2client.MultiForkProposalProvider,
	opts *api.EPBSProposalOpts,
) *proposalResult[*epbsProposalResponse] {
	providerOpts := *opts
	providerGraffiti, err := beaconblockproposal.GraffitiForProvider(ctx, provider, providerOpts.Graffiti)
	if err != nil {
		s.log.Warn().Str("error", beaconblockproposer.SafeError(err, name)).Msg("Failed to obtain node client; not updating graffiti")
	}
	providerOpts.Graffiti = providerGraffiti
	stableProvider := beaconblockproposer.StableProviderName(name)
	log := s.log.With().Str("provider", stableProvider).Uint64("slot", uint64(providerOpts.Slot)).Logger()

	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockproposal.first").Start(ctx, "ePBSBeaconBlockProposal", trace.WithAttributes(
		attribute.Int64("slot", util.SlotToInt64(opts.Slot)),
		attribute.String("request_id", beaconblockproposer.RequestID(ctx)),
		attribute.String("provider", stableProvider),
		attribute.String("proposal_root", "unknown"),
		attribute.String("source", "unknown"),
	))
	defer span.End()
	span.SetAttributes(beaconblockproposer.ClientDetailsAttributes(name)...)

	started := time.Now()
	result := fetchProviderProposal(s,
		log,
		name,
		"ePBS beacon block proposal",
		func() (*api.Response[*api.VersionedEPBSProposal], error) {
			return provider.EPBSProposal(ctx, &providerOpts)
		},
		func(response *api.Response[*api.VersionedEPBSProposal]) (*epbsProposalResponse, error) {
			if response == nil {
				return nil, errNoEPBSProposalResponse
			}

			return &epbsProposalResponse{
				provider: name,
				proposal: response.Data,
				metadata: response.Metadata,
			}, nil
		},
	)
	elapsed := time.Since(started)
	requestID := beaconblockproposer.RequestID(ctx)
	if result.err != nil {
		outcome := "error"
		rejectionReason := "provider_error"
		switch {
		case errors.Is(result.err, context.Canceled):
			outcome = "cancelled"
			rejectionReason = "selection_completed"
		case errors.Is(result.err, context.DeadlineExceeded):
			outcome = "timeout"
			rejectionReason = "deadline_reached"
		case errors.Is(result.err, errNoEPBSProposalResponse) && ctx.Err() == nil:
			outcome = "rejected"
			rejectionReason = "empty_response"
		case errors.Is(result.err, errNoEPBSProposalResponse):
			outcome = "cancelled"
			rejectionReason = "selection_completed"
		}
		s.logEPBSProviderFailure(opts.Slot, requestID, name, elapsed, result.err, outcome, rejectionReason)

		return result
	}
	result.proposal.elapsed = elapsed
	if proposal := result.proposal.proposal; proposal != nil {
		span.SetAttributes(attribute.String("source", beaconblockproposal.EPBSProposalSource(proposal, result.proposal.metadata)))
		if proposalRoot, err := proposal.Root(); err == nil {
			span.SetAttributes(attribute.String("proposal_root", proposalRoot.String()))
		}
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		// Selection has finished, so nothing reads this result.
		if result.proposal.proposal == nil {
			s.logEPBSProviderFailure(opts.Slot, requestID, name, elapsed, nil, "cancelled", "selection_completed")
		} else {
			s.logEPBSProviderResult(opts.Slot, requestID, result.proposal, "cancelled", "selection_completed")
		}
	}

	return result
}

// validateEPBSProposal rejects an invalid proposal, or a builder-backed Gloas proposal from a
// provider that has not accepted the current proposer preferences, and logs the outcome.
func (s *Service) validateEPBSProposal(requestID string,
	provider string,
	response *epbsProposalResponse,
	opts *api.EPBSProposalOpts,
) error {
	err := beaconblockproposal.ValidateEPBSProposal(response.proposal, opts.IncludePayload)
	if err != nil {
		s.log.Warn().Err(err).Msg("Discarding invalid ePBS proposal")
	} else if err = beaconblockproposal.ValidateBuilderBidReadiness(s.providerReadiness, provider, opts.Slot, response.proposal); err != nil {
		s.log.Warn().Str("provider", beaconblockproposer.StableProviderName(provider)).Msg("Discarding builder-backed ePBS proposal from provider without current preferences")
	}
	if err == nil {
		s.logEPBSProviderResult(opts.Slot, requestID, response, "accepted", "")

		return nil
	}
	rejectionReason := beaconblockproposal.RejectionReason(err)
	if response.proposal == nil || rejectionReason == "malformed_proposal" {
		s.logEPBSProviderFailure(opts.Slot, requestID, provider, response.elapsed, nil, "rejected", rejectionReason)
	} else {
		s.logEPBSProviderResult(opts.Slot, requestID, response, "rejected", rejectionReason)
	}

	return err
}

func (s *Service) logEPBSProviderFailure(slot phase0.Slot,
	requestID string,
	provider string,
	elapsed time.Duration,
	err error,
	outcome string,
	rejectionReason string,
) {
	event := s.log.Info().
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
		Str("outcome", outcome).
		Str("rejection_reason", rejectionReason)
	if err != nil {
		event = event.Str("error", beaconblockproposer.SafeError(err, provider))
	}
	event.Msg("ePBS proposal provider completed")
}

func (s *Service) logEPBSProviderResult(slot phase0.Slot,
	requestID string,
	response *epbsProposalResponse,
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
	beaconblockproposer.WithClientDetails(event, response.provider)
	event.Msg("ePBS proposal provider completed")
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

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	results := proposalResults(s.proposalProviders, func(name string,
		provider eth2client.MultiForkProposalProvider,
	) *proposalResult[*api.VersionedProposal] {
		providerOpts := *opts
		providerGraffiti, err := beaconblockproposal.GraffitiForProvider(ctx, provider, providerOpts.Graffiti)
		if err != nil {
			s.log.Warn().Err(err).Msg("Failed to obtain node client; not updating graffiti")
		}
		providerOpts.Graffiti = providerGraffiti
		log := s.log.With().Str("provider", name).Uint64("slot", uint64(providerOpts.Slot)).Logger()

		return fetchProviderProposal(s,
			log,
			name,
			"beacon block proposal",
			func() (*api.Response[*api.VersionedProposal], error) {
				return provider.Proposal(ctx, &providerOpts)
			},
			func(response *api.Response[*api.VersionedProposal]) (*api.VersionedProposal, error) {
				if response == nil || response.Data == nil {
					return nil, errors.New("beacon node returned no beacon block proposal")
				}

				return response.Data, nil
			},
		)
	})

	proposal, err := firstProposal(ctx,
		s.log,
		results,
		len(s.proposalProviders),
		nil,
		"failed to obtain beacon block proposal",
		"Failed to obtain beacon block proposal before timeout",
	)
	if err != nil {
		return nil, err
	}

	return &api.Response[*api.VersionedProposal]{
		Data:     proposal,
		Metadata: make(map[string]any),
	}, nil
}
