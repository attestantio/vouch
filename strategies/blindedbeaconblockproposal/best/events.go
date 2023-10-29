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
	"time"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
)

// HandleHeadEvent handles the "head" events from the beacon node.
func (s *Service) HandleHeadEvent(event *apiv1.Event) {
	if event.Data == nil {
		return
	}

	ctx := context.Background()

	data := event.Data.(*apiv1.HeadEvent)
	log := log.With().Uint64("slot", uint64(data.Slot)).Logger()
	log.Trace().Msg("Received head event")

	// An attestation in a block could be up to 1 epoch old.  We keep an
	// additional epoch's worth of attestations for target root matching,
	// for a total of 2 epochs of prior block information.
	if data.Slot < s.chainTime.CurrentSlot()-phase0.Slot(2*s.slotsPerEpoch) {
		// Block is too old for us to care about it.
		return
	}

	s.priorBlocksVotesMu.RLock()
	_, exists := s.priorBlocksVotes[data.Block]
	s.priorBlocksVotesMu.RUnlock()
	if exists {
		// We already have data for this block.
		return
	}

	blockResponse, err := s.signedBeaconBlockProvider.SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{
		Block: fmt.Sprintf("%#x", data.Block),
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain head beacon block")
		return
	}
	block := blockResponse.Data

	s.updateBlockVotes(ctx, block)
}

// updateBlockVotes updates the votes made in attestations for this block.
func (s *Service) updateBlockVotes(_ context.Context,
	block *spec.VersionedSignedBeaconBlock,
) {
	if block == nil {
		return
	}
	started := time.Now()

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

	s.priorBlocksVotesMu.Lock()
	s.priorBlocksVotes[root] = priorBlockVotes
	for k, v := range s.priorBlocksVotes {
		// Keep 2 epochs' worth of data as per comment above.
		if v.slot < slot-phase0.Slot(2*s.slotsPerEpoch) {
			delete(s.priorBlocksVotes, k)
		}
	}
	s.priorBlocksVotesMu.Unlock()

	log.Trace().Uint64("slot", uint64(slot)).Str("root", fmt.Sprintf("%#x", root[:])).Dur("elapsed", time.Since(started)).Msg("Set votes for slot")
}
