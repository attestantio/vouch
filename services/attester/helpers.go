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

package attester

import (
	"context"
	"sort"

	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
)

// MergeDuties merges attester duties given by an Ethereum 2 client into vouch's per-slot structure.
func MergeDuties(ctx context.Context, attesterDuties []*api.AttesterDuty) ([]*Duty, error) {
	duties := make([]*Duty, 0)
	if len(attesterDuties) == 0 {
		return duties, nil
	}

	validatorIndices := make(map[phase0.Slot][]phase0.ValidatorIndex)
	committeeIndices := make(map[phase0.Slot][]phase0.CommitteeIndex)
	validatorCommitteeIndices := make(map[phase0.Slot][]uint64)
	committeeLengths := make(map[phase0.Slot]map[phase0.CommitteeIndex]uint64)
	committeesAtSlots := make(map[phase0.Slot]uint64)

	// Make an educated guess at the capacity for our arrays based on the number of attester duties.
	arrayCap := util.IntToUint64(len(attesterDuties) / 32)

	// Sort the response by slot, then committee index, then validator index.
	sort.Slice(attesterDuties, func(i int, j int) bool {
		if attesterDuties[i].Slot < attesterDuties[j].Slot {
			return true
		}
		if attesterDuties[i].Slot > attesterDuties[j].Slot {
			return false
		}
		if attesterDuties[i].CommitteeIndex < attesterDuties[j].CommitteeIndex {
			return true
		}
		if attesterDuties[i].CommitteeIndex > attesterDuties[j].CommitteeIndex {
			return false
		}
		return attesterDuties[i].ValidatorIndex < attesterDuties[j].ValidatorIndex
	})

	for _, duty := range attesterDuties {
		// Future optimisation (maybe; depends how much effort it is to fetch validator status here):
		// There are three states where a validator is given duties: active, exiting and slashing.
		// However, if the validator is slashing its attestations are ignored by the network.
		// Hence, if the validator is slashed we don't need to include its duty.

		if _, exists := validatorIndices[duty.Slot]; !exists {
			validatorIndices[duty.Slot] = make([]phase0.ValidatorIndex, 0, arrayCap)
			committeeIndices[duty.Slot] = make([]phase0.CommitteeIndex, 0, arrayCap)
			committeeLengths[duty.Slot] = make(map[phase0.CommitteeIndex]uint64)
			committeesAtSlots[duty.Slot] = duty.CommitteesAtSlot
		}
		committeesAtSlots[duty.Slot] = duty.CommitteesAtSlot
		validatorIndices[duty.Slot] = append(validatorIndices[duty.Slot], duty.ValidatorIndex)
		committeeIndices[duty.Slot] = append(committeeIndices[duty.Slot], duty.CommitteeIndex)
		committeeLengths[duty.Slot][duty.CommitteeIndex] = duty.CommitteeLength
		validatorCommitteeIndices[duty.Slot] = append(validatorCommitteeIndices[duty.Slot], duty.ValidatorCommitteeIndex)
	}

	for slot := range validatorIndices {
		if duty, err := NewDuty(
			ctx,
			slot,
			committeesAtSlots[slot],
			validatorIndices[slot],
			committeeIndices[slot],
			validatorCommitteeIndices[slot],
			committeeLengths[slot],
		); err == nil {
			duties = append(duties, duty)
		}
	}

	// Order the attester duties by slot.
	sort.Slice(duties, func(i int, j int) bool {
		if duties[i].Slot() < duties[j].Slot() {
			return true
		}
		if duties[i].Slot() > duties[j].Slot() {
			return false
		}
		return true
	})

	return duties, nil
}
