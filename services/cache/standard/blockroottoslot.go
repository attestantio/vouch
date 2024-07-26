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

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// BlockRootToSlot provides the slot for a given block root.
func (s *Service) BlockRootToSlot(ctx context.Context, root phase0.Root) (phase0.Slot, error) {
	s.blockRootToSlotMu.RLock()
	slot, exists := s.blockRootToSlot[root]
	s.blockRootToSlotMu.RUnlock()
	if exists {
		log.Trace().Stringer("root", root).Uint64("slot", uint64(slot)).Msg("Obtained slot from cache")
		monitorBlockRootToSlot("hit")
		return slot, nil
	}

	if headersProvider, isProvider := s.consensusClient.(eth2client.BeaconBlockHeadersProvider); isProvider {
		blockResponse, err := headersProvider.BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{
			Block: root.String(),
		})
		if err != nil {
			monitorBlockRootToSlot("failed")
			return 0, errors.Wrap(err, "failed to obtain block header")
		}
		block := blockResponse.Data

		slot = block.Header.Message.Slot
		s.SetBlockRootToSlot(root, slot)

		log.Trace().Stringer("root", root).Uint64("slot", uint64(slot)).Msg("Obtained slot from block header")
		monitorBlockRootToSlot("miss (block header)")
		return slot, nil
	}

	if blocksProvider, isProvider := s.consensusClient.(eth2client.SignedBeaconBlockProvider); isProvider {
		blockResponse, err := blocksProvider.SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{
			Block: root.String(),
		})
		if err != nil {
			monitorBlockRootToSlot("failed")
			return 0, errors.Wrap(err, "failed to obtain block")
		}
		block := blockResponse.Data
		slot, err = block.Slot()
		if err != nil {
			monitorBlockRootToSlot("failed")
			return 0, errors.Wrap(err, "failed to obtain block slot")
		}

		s.SetBlockRootToSlot(root, slot)

		log.Trace().Stringer("root", root).Uint64("slot", uint64(slot)).Msg("Obtained slot from block")
		monitorBlockRootToSlot("miss (block)")
		return slot, nil
	}

	monitorBlockRootToSlot("miss")
	return 0, errors.New("failed to obtain slot from cache or client")
}

// SetBlockRootToSlot sets the block root to slot mapping.
func (s *Service) SetBlockRootToSlot(root phase0.Root, slot phase0.Slot) {
	s.blockRootToSlotMu.Lock()
	s.blockRootToSlot[root] = slot
	monitorBlockRootToSlotEntriesUpdated(len(s.blockRootToSlot))
	s.blockRootToSlotMu.Unlock()
}

// cleanBlockRootToSlot cleans out old entries in the cache.
func (s *Service) cleanBlockRootToSlot(_ context.Context, _ interface{}) {
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

	log.Trace().Int("cleaned", cleaned).Msg("Cleaned block root to slot cache")
}
