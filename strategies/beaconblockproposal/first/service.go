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
	"github.com/attestantio/vouch/services/metrics"
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

func fetchProviderProposal[T any](s *Service,
	log zerolog.Logger,
	name string,
	operation string,
	request func() (*api.Response[T], error),
	proposal func(*api.Response[T]) (T, error),
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
	validate func(T) error,
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
			if err := validate(result.proposal); err != nil {
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
	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockproposal.first").Start(ctx, "EPBSProposal", trace.WithAttributes(
		attribute.Int64("slot", util.SlotToInt64(opts.Slot)),
	))
	defer span.End()

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	results := proposalResults(s.proposalProviders, func(name string,
		provider eth2client.MultiForkProposalProvider,
	) *proposalResult[*api.VersionedEPBSProposal] {
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
			"ePBS beacon block proposal",
			func() (*api.Response[*api.VersionedEPBSProposal], error) {
				return provider.EPBSProposal(ctx, &providerOpts)
			},
			func(response *api.Response[*api.VersionedEPBSProposal]) (*api.VersionedEPBSProposal, error) {
				if response == nil {
					return nil, errors.New("beacon node returned no ePBS proposal response")
				}

				return response.Data, nil
			},
		)
	})

	proposal, err := firstProposal(ctx,
		s.log,
		results,
		len(s.proposalProviders),
		func(proposal *api.VersionedEPBSProposal) error {
			return s.validateEPBSProposal(proposal, opts.IncludePayload)
		},
		"failed to obtain ePBS beacon block proposal",
		"Failed to obtain ePBS beacon block proposal before timeout",
	)
	if err != nil {
		return nil, err
	}

	return &api.Response[*api.VersionedEPBSProposal]{
		Data:     proposal,
		Metadata: make(map[string]any),
	}, nil
}

func (s *Service) validateEPBSProposal(proposal *api.VersionedEPBSProposal, includePayload *bool) error {
	err := beaconblockproposal.ValidateEPBSProposal(proposal, includePayload)
	if err != nil {
		s.log.Warn().Err(err).Msg("Discarding invalid ePBS proposal")
	}

	return err
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
