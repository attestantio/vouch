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

package standard

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/attestantio/go-block-relay/services/blockauctioneer"
	builderspec "github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
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
	res := &blockauctioneer.Results{
		Values: make(map[string]*big.Int),
	}

	// TODO parallelise.
	for _, builderBidProvider := range s.builderBidProviders {
		log := log.With().Str("bidder", builderBidProvider.Address()).Logger()
		builderBid, err := builderBidProvider.BuilderBid(ctx, slot, parentHash, pubkey)
		if err != nil {
			// Log but continue to the next builder.
			log.Warn().Err(err).Msg("Failed to obtain builder bid")
			continue
		}
		if e := log.Trace(); e.Enabled() {
			data, err := json.Marshal(builderBid)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to marshal builder bid")
			} else {
				e.Str("builder", builderBidProvider.Address()).RawJSON("builder_bid", data).Msg("Obtained builder bid")
			}
		}
		if builderBid.IsEmpty() {
			// Log but continue to the next builder.
			log.Warn().Err(err).Msg("Builder bid empty")
			continue
		}
		switch builderBid.Version {
		case consensusspec.DataVersionBellatrix:
			res.Values[builderBidProvider.Address()] = builderBid.Data.Message.Value.ToBig()
			if res.Bid == nil || res.Bid.Data.Message.Value.Cmp(builderBid.Data.Message.Value) < 0 {
				// New max bid.
				res.Bid = builderBid
				res.Provider = builderBidProvider
			}
		default:
			// Log but continue to the next builder.
			log.Warn().Stringer("version", builderBid.Version).Msg("Unhandled builder bid data version")
			continue
		}
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

	return res, nil
}
