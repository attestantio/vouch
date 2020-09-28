// Copyright © 2020 Attestant Limited.
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

package chaintime

import "time"

// Service provides a number of functions for calculating chain-related times.
type Service interface {
	// GenesisTime provides the time of the chain's genesis.
	GenesisTime() time.Time
	// StartOfSlot provides the time at which a given slot starts.
	StartOfSlot(slot uint64) time.Time
	// StartOfEpoch provides the time at which a given epoch starts.
	StartOfEpoch(epoch uint64) time.Time
	// CurrentSlot provides the current slot.
	CurrentSlot() uint64
	// CurrentEpoch provides the current epoch.
	CurrentEpoch() uint64
	// SlotToEpoch provides the epoch of the given slot.
	SlotToEpoch(slot uint64) uint64
	// FirstSlotOfEpoch provides the first slot of the given epoch.
	FirstSlotOfEpoch(epoch uint64) uint64
}
