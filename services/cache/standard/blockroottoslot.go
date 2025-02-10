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

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// BlockRootToSlot provides the slot for a given block root.
func (s *Service) BlockRootToSlot(ctx context.Context, root phase0.Root) (phase0.Slot, error) {
	s.blockRootToSlotMu.RLock()
	slot, exists := s.blockRootToSlot[root]
	s.blockRootToSlotMu.RUnlock()
	if exists {
		s.log.Trace().Stringer("root", root).Uint64("slot", uint64(slot)).Msg("Obtained slot from cache")
		monitorBlockRootToSlot("hit")
		return slot, nil
	}

	blockResponse, err := s.beaconBlockHeadersProvider.BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{
		Block: root.String(),
	})
	if err != nil {
		monitorBlockRootToSlot("failed")
		return 0, errors.Wrap(err, "failed to obtain block header")
	}

	monitorBlockRootToSlot("miss")

	if isBlockHeaderResponseValid(blockResponse) {
		fetchedSlot := blockResponse.Data.Header.Message.Slot
		s.SetBlockRootToSlot(root, fetchedSlot)
		s.log.Trace().Stringer("root", root).Uint64("slot", uint64(fetchedSlot)).Msg("Obtained slot from block header")
		return fetchedSlot, nil
	}

	return 0, errors.New("failed to obtain block header - invalid response")
}

func isBlockHeaderResponseValid(blockResponse *api.Response[*apiv1.BeaconBlockHeader]) bool {
	return blockResponse != nil &&
		blockResponse.Data != nil &&
		blockResponse.Data.Header != nil &&
		blockResponse.Data.Header.Message != nil
}

// SetBlockRootToSlot sets the block root to slot mapping.
func (s *Service) SetBlockRootToSlot(root phase0.Root, slot phase0.Slot) {
	s.blockRootToSlotMu.Lock()
	s.blockRootToSlot[root] = slot
	monitorBlockRootToSlotEntriesUpdated(len(s.blockRootToSlot))
	s.log.Trace().Uint64("slot", uint64(slot)).Stringer("root", root).Msg("Stored root for slot")
	s.blockRootToSlotMu.Unlock()
}

// cleanBlockRootToSlot cleans out old entries in the cache.
func (s *Service) cleanBlockRootToSlot(_ context.Context) {
	// Keep 64 epochs of information around, to cover most scenarios.
	safetyMargin := phase0.Epoch(64)
	if s.chainTime.CurrentEpoch() <= safetyMargin {
		return
	}
	minSlot := s.chainTime.FirstSlotOfEpoch(s.chainTime.CurrentEpoch() - safetyMargin)

	s.blockRootToSlotMu.Lock()
	cleaned := 0
	for root, slot := range s.blockRootToSlot {
		if slot < minSlot {
			delete(s.blockRootToSlot, root)
			cleaned++
		}
	}
	monitorBlockRootToSlotEntriesUpdated(len(s.blockRootToSlot))
	s.blockRootToSlotMu.Unlock()

	s.log.Trace().Int("cleaned", cleaned).Msg("Cleaned block root to slot cache")
}
