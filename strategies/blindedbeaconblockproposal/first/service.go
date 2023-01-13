// Copyright © 2022 Attestant Limited.
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
	"bytes"
	"context"
	"time"

	builderspec "github.com/attestantio/go-builder-client/spec"
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Service is the provider for beacon block proposals.
type Service struct {
	clientMonitor                       metrics.ClientMonitor
	chainTime                           chaintime.Service
	blindedBeaconBlockProposalProviders map[string]eth2client.BlindedBeaconBlockProposalProvider
	timeout                             time.Duration
}

// module-wide log.
var log zerolog.Logger

var zeroFeeRecipient bellatrix.ExecutionAddress

// New creates a new beacon block propsal strategy.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("strategy", "blindedbeaconblockproposal").Str("impl", "first").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		chainTime:                           parameters.chainTime,
		blindedBeaconBlockProposalProviders: parameters.blindedBeaconBlockProposalProviders,
		timeout:                             parameters.timeout,
		clientMonitor:                       parameters.clientMonitor,
	}

	return s, nil
}

// BlindedBeaconBlockProposal provides the first blinded beacon block proposal from a number of beacon nodes.
func (s *Service) BlindedBeaconBlockProposal(ctx context.Context, slot phase0.Slot, randaoReveal phase0.BLSSignature, graffiti []byte) (*api.VersionedBlindedBeaconBlock, error) {
	return s.BlindedBeaconBlockProposalWithExpectedPayload(ctx, slot, randaoReveal, graffiti, nil)
}

// BlindedBeaconBlockProposalWithExpectedPayload fetches a blinded proposed beacon block for signing.
func (s *Service) BlindedBeaconBlockProposalWithExpectedPayload(ctx context.Context,
	slot phase0.Slot,
	randaoReveal phase0.BLSSignature,
	graffiti []byte,
	bid *builderspec.VersionedSignedBuilderBid,
) (
	*api.VersionedBlindedBeaconBlock,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.blindedbeaconblockproposal.first").Start(ctx, "BlindedBeaconBlockProposal", trace.WithAttributes(
		attribute.Int64("slot", int64(slot)),
	))
	defer span.End()

	// We create a cancelable context with a timeout.  As soon as the first provider has responded we
	// cancel the context to cancel the other requests.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	proposalCh := make(chan *api.VersionedBlindedBeaconBlock, 1)
	for name, provider := range s.blindedBeaconBlockProposalProviders {
		go func(ctx context.Context, name string, provider eth2client.BlindedBeaconBlockProposalProvider, ch chan *api.VersionedBlindedBeaconBlock) {
			log := log.With().Str("provider", name).Uint64("slot", uint64(slot)).Logger()

			started := time.Now()
			proposal, err := provider.BlindedBeaconBlockProposal(ctx, slot, randaoReveal, graffiti)
			s.clientMonitor.ClientOperation(name, "blinded beacon block proposal", err == nil, time.Since(started))
			if err != nil {
				log.Warn().Err(err).Msg("Failed to obtain blinded beacon block proposal")
				return
			}
			if proposal == nil {
				log.Warn().Err(err).Msg("Returned empty blinded beacon block proposal")
				return
			}
			log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained blinded beacon block proposal")
			feeRecipient, err := proposal.FeeRecipient()
			if err != nil {
				log.Warn().Err(err).Msg("Failed to obtain blinded beacon block fee recipient")
				return
			}
			if bytes.Equal(feeRecipient[:], zeroFeeRecipient[:]) {
				log.Warn().Msg("Blinded beacon block proposal response has 0 fee recipient")
				return
			}
			executionTimestamp, err := proposal.Timestamp()
			if err != nil {
				log.Warn().Err(err).Msg("Failed to obtain blinded beacon block timestamp")
				return
			}
			if int64(executionTimestamp) != s.chainTime.StartOfSlot(slot).Unix() {
				log.Warn().Msg("Blinded beacon block proposal response has incorrect timestamp")
				return
			}
			if bid != nil {
				bidTransactionsRoot, err := bid.TransactionsRoot()
				if err == nil {
					proposalTransactionsRoot, err := proposal.TransactionsRoot()
					if err != nil {
						log.Warn().Err(err).Msg("Failed to obtain blinded beacon block transactions root")
						return
					}
					if !bytes.Equal(bidTransactionsRoot[:], proposalTransactionsRoot[:]) {
						log.Warn().Stringer("proposal_transactions_root", proposalTransactionsRoot).Stringer("bid_transactions_root", bidTransactionsRoot).Msg("Transactions root mismatch")
						return
					}
				}
			}

			ch <- proposal
		}(ctx, name, provider, proposalCh)
	}

	select {
	case <-ctx.Done():
		cancel()
		log.Warn().Msg("Failed to obtain blinded beacon block proposal before timeout")
		return nil, errors.New("failed to obtain blinded beacon block proposal before timeout")
	case proposal := <-proposalCh:
		cancel()
		return proposal, nil
	}
}
