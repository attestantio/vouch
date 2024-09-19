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

package standard

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/attestantio/go-block-relay/services/blockauctioneer"
	builderclient "github.com/attestantio/go-builder-client"
	"github.com/attestantio/go-builder-client/api/deneb"
	builderspec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// AuctionBlock obtains the best available use of the block space.
func (s *Service) AuctionBlock(ctx context.Context,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
) (
	*blockauctioneer.Results,
	error,
) {
	account, err := s.accountsProvider.AccountByPublicKey(ctx, pubkey)
	if err != nil {
		return nil, errors.New("no account found for public key")
	}

	return s.auctionBlock(ctx, slot, parentHash, pubkey, account)
}

func (s *Service) auctionBlock(ctx context.Context,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
	account e2wtypes.Account,
) (
	*blockauctioneer.Results,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "auctionBlock")
	defer span.End()

	s.executionConfigMu.RLock()
	proposerConfig, err := s.ProposerConfig(ctx, account, pubkey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain proposer configuration")
	}
	s.executionConfigMu.RUnlock()

	if len(proposerConfig.Relays) == 0 {
		s.log.Trace().Msg("No relays in proposer configuration")
		return &blockauctioneer.Results{
			Participation: make(map[string]*blockauctioneer.Participation),
			AllProviders:  make([]builderclient.BuilderBidProvider, 0),
			Providers:     make([]builderclient.BuilderBidProvider, 0),
		}, nil
	}

	res, err := s.builderBidProvider.BuilderBid(ctx, slot, parentHash, pubkey, proposerConfig, s.builderConfigs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain builder bid")
	}

	var bid *builderspec.VersionedSignedBuilderBid
	if res.WinningParticipation != nil {
		bid = res.WinningParticipation.Bid
	}

	s.cacheBid(ctx, slot, parentHash, pubkey, bid)

	s.logParticipation(ctx, span, slot, res)

	return res, nil
}

func (s *Service) cacheBid(_ context.Context,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
	bid *builderspec.VersionedSignedBuilderBid,
) {
	if bid == nil {
		// No bid supplied; create a dummy for the purposes of caching so that if asked for this bid
		// we can actively respond to say we don't have anything (as opposed to attempting to fetch
		// a bid when we're queried).
		s.log.Trace().Msg("Bid is nil; creating dummy")
		bid = &builderspec.VersionedSignedBuilderBid{
			Version: spec.DataVersionDeneb,
			Deneb: &deneb.SignedBuilderBid{
				Message: &deneb.BuilderBid{
					Value: uint256.NewInt(0),
				},
			},
		}
	}

	key := fmt.Sprintf("%d", slot)
	subKey := fmt.Sprintf("%x:%x", parentHash, pubkey)
	s.log.Trace().Str("key", key).Str("subkey", subKey).Msg("Caching bid")
	s.builderBidsCacheMu.Lock()
	if _, exists := s.builderBidsCache[key]; !exists {
		s.builderBidsCache[key] = make(map[string]*builderspec.VersionedSignedBuilderBid)
	}
	s.builderBidsCache[key][subKey] = bid
	s.builderBidsCacheMu.Unlock()
}

func (s *Service) logParticipation(_ context.Context,
	span trace.Span,
	slot phase0.Slot,
	res *blockauctioneer.Results,
) {
	if res.WinningParticipation == nil {
		// Nothing to log.
		return
	}

	selectedProviders := make(map[string]struct{})
	for _, provider := range res.Providers {
		selectedProviders[strings.ToLower(provider.Address())] = struct{}{}
	}

	winningScore := res.WinningParticipation.Score
	winningValue, err := res.WinningParticipation.Bid.Value()
	if err != nil {
		s.log.Warn().Err(err).Msg("Failed to obtain value of winning bid")
		return
	}

	for provider, participation := range res.Participation {
		providerScore := participation.Score
		scoreDelta := new(big.Int).Sub(winningScore, providerScore)
		providerValue, err := participation.Bid.Value()
		if err != nil {
			s.log.Warn().Str("provider", provider).Err(err).Msg("Failed to obtain value of participating bid")
			continue
		}
		valueDelta := new(big.Int).Sub(winningValue.ToBig(), providerValue.ToBig())

		_, isSelected := selectedProviders[strings.ToLower(provider)]
		if !isSelected {
			monitorBuilderBidDelta(provider, valueDelta)
		}

		var logger *zerolog.Event
		if s.logResults {
			//nolint:zerologlint
			logger = s.log.Info()
		} else {
			//nolint:zerologlint
			logger = s.log.Trace()
		}
		logger.
			Uint64("slot", uint64(slot)).
			Str("provider", provider).
			Stringer("value", providerValue).
			Stringer("value_delta", valueDelta).
			Stringer("score", providerScore).
			Stringer("score_delta", scoreDelta).
			Bool("selected", isSelected).
			Msg("Auction participant")
	}

	// Add result to trace.
	// Has to be a string due to the potential size being >maxint64.
	span.SetAttributes(attribute.String("value", winningValue.ToBig().String()))
	providerAddresses := make([]string, 0, len(selectedProviders))
	for k := range selectedProviders {
		providerAddresses = append(providerAddresses, k)
	}
	span.SetAttributes(attribute.StringSlice("providers", providerAddresses))
}
