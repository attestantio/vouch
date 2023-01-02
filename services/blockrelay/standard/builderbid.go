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
	"time"

	"github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
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
	_, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "BuilderBid")
	defer span.End()

	started := time.Now()

	log.Trace().Uint64("slot", uint64(slot)).Str("parent_hash", fmt.Sprintf("%#x", parentHash)).Str("pubkey", fmt.Sprintf("%#x", pubkey)).Msg("Builder bid called")

	// Fetch the matching header from the cache.
	key := fmt.Sprintf("%d", slot)
	subKey := fmt.Sprintf("%x:%x", parentHash, pubkey)
	s.builderBidsCacheMu.RLock()
	slotBuilderBids, exists := s.builderBidsCache[key]
	if !exists {
		s.builderBidsCacheMu.RUnlock()
		log.Debug().Str("key", key).Msg("Builder bid not found (slot)")
		monitorBuilderBid(time.Since(started), false)
		return nil, errors.New("builder bid not known (slot)")
	}
	builderBid, exists := slotBuilderBids[subKey]
	s.builderBidsCacheMu.RUnlock()
	if !exists {
		log.Debug().Str("key", key).Str("subkey", subKey).Msg("Builder bid not found (subkey)")
		monitorBuilderBid(time.Since(started), false)
		return nil, errors.New("builder bid not known (subkey)")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(builderBid)
		if err == nil {
			e.RawJSON("bid", data).Msg("Builder bid obtained to provide to requesting beacon node")
		}
	}

	monitorBuilderBid(time.Since(started), true)
	return builderBid, nil
}
