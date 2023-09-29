// Copyright © 2022, 2023 Attestant Limited.
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
	builderspec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
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
	ctx, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "AuctionBlock")
	defer span.End()

	account, err := s.accountsProvider.AccountByPublicKey(ctx, pubkey)
	if err != nil {
		return nil, errors.New("no account found for public key")
	}
	s.executionConfigMu.RLock()
	proposerConfig, err := s.executionConfig.ProposerConfig(ctx, account, pubkey, s.fallbackFeeRecipient, s.fallbackGasLimit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain proposer configuration")
	}
	s.executionConfigMu.RUnlock()

	if len(proposerConfig.Relays) == 0 {
		log.Trace().Msg("No relays in proposer configuration")
		return &blockauctioneer.Results{}, nil
	}

	res, err := s.builderBidProvider.BuilderBid(ctx, slot, parentHash, pubkey, proposerConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain builder bid")
	}

	if res.Bid != nil {
		key := fmt.Sprintf("%d", slot)
		subKey := fmt.Sprintf("%x:%x", parentHash, pubkey)
		s.builderBidsCacheMu.Lock()
		if _, exists := s.builderBidsCache[key]; !exists {
			s.builderBidsCache[key] = make(map[string]*builderspec.VersionedSignedBuilderBid)
		}
		s.builderBidsCache[key][subKey] = res.Bid
		s.builderBidsCacheMu.Unlock()
	}

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
				if s.logResults {
					log.Info().Uint64("slot", uint64(slot)).Str("provider", provider).Stringer("value", value).Stringer("delta", delta).Bool("selected", isSelected).Msg("Auction participant")
				} else {
					log.Trace().Uint64("slot", uint64(slot)).Str("provider", provider).Stringer("value", value).Stringer("delta", delta).Bool("selected", isSelected).Msg("Auction participant")
				}
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
