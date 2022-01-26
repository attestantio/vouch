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

package best

import (
	"context"
	"fmt"

	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
)

// HandleHeadEvent handles the "head" events from the beacon node.
func (s *Service) HandleHeadEvent(event *api.Event) {
	if event.Data == nil {
		return
	}

	ctx := context.Background()

	data := event.Data.(*api.HeadEvent)
	log := log.With().Uint64("slot", uint64(data.Slot)).Logger()
	log.Trace().Msg("Received head event")

	if data.Slot != s.chainTime.CurrentSlot() {
		return
	}

	block, err := s.signedBeaconBlockProvider.SignedBeaconBlock(ctx, fmt.Sprintf("%#x", data.Block))
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain head beacon block")
		return
	}

	s.updateBlockVotes(ctx, block)
}

// updateBlockVotes updates the votes made in attestations for this block.
func (s *Service) updateBlockVotes(ctx context.Context,
	block *spec.VersionedSignedBeaconBlock,
) {
	if block == nil {
		return
	}

	slot, err := block.Slot()
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain proposed block's slot")
		return
	}
	attestations, err := block.Attestations()
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain proposed block's attestations")
		return
	}

	votes := make(map[phase0.Slot]map[phase0.CommitteeIndex]bitfield.Bitlist)
	for _, attestation := range attestations {
		data := attestation.Data
		_, exists := votes[data.Slot]
		if !exists {
			votes[data.Slot] = make(map[phase0.CommitteeIndex]bitfield.Bitlist)
		}
		_, exists = votes[data.Slot][data.Index]
		if !exists {
			votes[data.Slot][data.Index] = bitfield.NewBitlist(attestation.AggregationBits.Len())
		}
		for i := uint64(0); i < attestation.AggregationBits.Len(); i++ {
			if attestation.AggregationBits.BitAt(i) {
				votes[data.Slot][data.Index].SetBitAt(i, true)
			}
		}
	}

	parentRoot, err := block.ParentRoot()
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain proposed block's parent root")
		return
	}

	root, err := block.Root()
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain proposed block's root")
		return
	}

	priorBlockVotes := &priorBlockVotes{
		root:   root,
		parent: parentRoot,
		slot:   slot,
		votes:  votes,
	}

	s.priorBlocksMu.Lock()
	s.priorBlocks[root] = priorBlockVotes
	for k, v := range s.priorBlocks {
		if v.slot < slot-phase0.Slot(s.slotsPerEpoch) {
			delete(s.priorBlocks, k)
		}
	}
	s.priorBlocksMu.Unlock()

	log.Trace().Uint64("slot", uint64(slot)).Msg("Set votes for slot")
}
