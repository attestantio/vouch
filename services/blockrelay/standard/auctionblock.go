// Copyright © 2022 - 2024 Attestant Limited.
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
		log.Trace().Msg("No relays in proposer configuration")
		return &blockauctioneer.Results{
			Values: make(map[string]*big.Int),
		}, nil
	}

	res, err := s.builderBidProvider.BuilderBid(ctx, slot, parentHash, pubkey, proposerConfig, s.excludedBuilders, s.privilegedBuilders)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain builder bid")
	}

	bidToCache := res.Bid
	if bidToCache == nil {
		// No bid returned; create a dummy for the purposes of caching.
		log.Trace().Msg("Bid is nil; creating dummy")
		bidToCache = &builderspec.VersionedSignedBuilderBid{
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
	log.Trace().Str("key", key).Str("subkey", subKey).Msg("Caching bid")
	s.builderBidsCacheMu.Lock()
	if _, exists := s.builderBidsCache[key]; !exists {
		s.builderBidsCache[key] = make(map[string]*builderspec.VersionedSignedBuilderBid)
	}
	s.builderBidsCache[key][subKey] = bidToCache
	s.builderBidsCacheMu.Unlock()

	selectedProviders := make(map[string]struct{})
	for _, provider := range res.Providers {
		selectedProviders[strings.ToLower(provider.Address())] = struct{}{}
	}

	if res.Bid != nil {
		val, err := res.Bid.Value()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to obtain bid value")
		} else {
			// Update metrics.
			for provider, value := range res.Values {
				delta := new(big.Int).Sub(val.ToBig(), value)
				_, isSelected := selectedProviders[strings.ToLower(provider)]
				if !isSelected {
					monitorBuilderBidDelta(provider, delta)
				}
				var logger *zerolog.Event
				if s.logResults {
					//nolint:zerologlint
					logger = log.Info()
				} else {
					//nolint:zerologlint
					logger = log.Trace()
				}
				logger.
					Uint64("slot", uint64(slot)).
					Str("provider", provider).
					Stringer("value", value).
					Stringer("delta", delta).
					Bool("selected", isSelected).
					Msg("Auction participant")
			}

			// Add result to trace.
			// Has to be a string due to the potential size being >maxint64.
			span.SetAttributes(attribute.String("value", val.ToBig().String()))
			providerAddresses := make([]string, 0, len(selectedProviders))
			for k := range selectedProviders {
				providerAddresses = append(providerAddresses, k)
			}
			span.SetAttributes(attribute.StringSlice("providers", providerAddresses))
		}
	}

	return res, nil
}
