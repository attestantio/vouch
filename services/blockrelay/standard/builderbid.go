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
	"time"

	"github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// BuilderBid provides a builder bid.
func (s *Service) BuilderBid(ctx context.Context,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
) (
	*spec.VersionedSignedBuilderBid,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "BuilderBid", trace.WithAttributes(
		attribute.Int64("slot", util.SlotToInt64(slot)),
	))
	defer span.End()

	log := s.log.With().Uint64("slot", uint64(slot)).Stringer("parent_hash", parentHash).Stringer("pubkey", pubkey).Logger()
	log.Trace().Msg("Builder bid called")

	builderBid, exists := s.cachedBid(ctx, slot, parentHash, pubkey)
	if !exists {
		log.Trace().Msg("Builder bid not available")
	}
	if builderBid != nil {
		value, err := builderBid.Value()
		if err != nil {
			log.Trace().Msg("Builder bid value not available")
		}

		if value.Sign() > 0 {
			// We have a cached bid with a value; provide it.
			return builderBid, nil
		}

		// We have a cached bid with no value, which means that we went through the auction and failed to obtain a bid that we
		// could accept.  Return no bid but no error.
		return nil, nil
	}

	// If we reach here it means that we have no cached bid at all.  This can happen if the validator is not controlled by Vouch, or
	// if there has been a reorg.  Hence there is the possibility that there are multiple beacon nodes that will be calling this
	// simultaneously, so block with a mutex and re-check after we obtain the mutex to see if there is now cached data.
	s.builderBidMu.Lock()
	defer s.builderBidMu.Unlock()
	builderBid, exists = s.cachedBid(ctx, slot, parentHash, pubkey)
	if !exists {
		log.Trace().Msg("Builder bid still not available")
	}
	if builderBid != nil {
		value, err := builderBid.Value()
		if err != nil {
			log.Trace().Msg("Builder bid value still not available")
		}

		if value.Sign() > 0 {
			// We have a cached bid with a value; provide it.
			return builderBid, nil
		}

		// We have a cached bid with no value, which means that we went through the auction and failed to obtain a bid that we
		// could accept.  Return no bid but no error.
		return nil, nil
	}

	// We have no bid, attempt to fetch one.
	return s.immediateBuilderBid(ctx, slot, parentHash, pubkey)
}

// immediateBuilderBid obtains a single builder bid for a validator, carrying out an immediate auction.
func (s *Service) immediateBuilderBid(ctx context.Context,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
) (
	*spec.VersionedSignedBuilderBid,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "oneShotBuilderBid")
	defer span.End()
	started := time.Now()

	s.log.Trace().Uint64("slot", uint64(slot)).Stringer("pubkey", pubkey).Msg("Obtaining immediate builder bid for validator")

	results, err := s.auctionBlock(ctx, slot, parentHash, pubkey, nil)
	if err != nil || results == nil || results.WinningParticipation == nil {
		monitorBuilderBid(time.Since(started), false)
		return nil, err
	}

	monitorBuilderBid(time.Since(started), true)

	return results.WinningParticipation.Bid, nil
}

func (s *Service) cachedBid(_ context.Context,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
) (
	*spec.VersionedSignedBuilderBid,
	bool,
) {
	// Fetch the matching header from the cache.
	key := fmt.Sprintf("%d", slot)
	subkey := fmt.Sprintf("%x:%x", parentHash, pubkey)
	s.builderBidsCacheMu.RLock()
	slotBuilderBids, exists := s.builderBidsCache[key]
	if !exists {
		s.builderBidsCacheMu.RUnlock()
		s.log.Debug().Str("key", key).Msg("Builder bid not known (slot)")
		return nil, false
	}
	builderBid, exists := slotBuilderBids[subkey]
	s.builderBidsCacheMu.RUnlock()
	if !exists {
		s.log.Debug().Str("subkey", subkey).Msg("Builder bid not known (subkey)")
		return nil, false
	}

	return builderBid, true
}
