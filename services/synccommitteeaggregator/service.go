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

package synccommitteeaggregator

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Duty contains information about a sync committee aggregation duty.
type Duty struct {
	// Slot is the slot of the sync committee aggregation; required for obtaining the aggregate.
	Slot phase0.Slot

	// ValidatorIndices are the validators that aggregate for this slot.
	ValidatorIndices []phase0.ValidatorIndex

	// SelectionProofs are the selection proofs of the subcommittees for which each validator aggregates.
	SelectionProofs map[phase0.ValidatorIndex]map[uint64]phase0.BLSSignature

	// Accounts is used to sign the sync committee contribution and proof.
	Accounts map[phase0.ValidatorIndex]e2wtypes.Account
}

// Service is the sync committee aggregation service.
type Service interface {
	// SetBeaconBlockRoot sets the beacon block root used for a given slot.
	SetBeaconBlockRoot(slot phase0.Slot, root phase0.Root)

	// Aggregate carries out aggregation for a slot and committee.
	Aggregate(ctx context.Context, duty *Duty)
}
