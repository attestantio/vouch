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

package first

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/vouch/services/metrics"
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
	proposalProviders map[string]eth2client.ProposalProvider
	timeout           time.Duration
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
					log.Warn().Err(err).Msg("Failed to obtain beacon block proposal")
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
		s.log.Warn().Msg("Failed to obtain beacon block proposal before timeout")
		return nil, errors.New("failed to obtain beacon block proposal before timeout")
	case proposal := <-proposalCh:
		cancel()
		return &api.Response[*api.VersionedProposal]{
			Data:     proposal,
			Metadata: make(map[string]any),
		}, nil
	}
}
