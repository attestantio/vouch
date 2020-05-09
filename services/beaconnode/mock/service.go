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

package mock

// BeaconNode is a mock beacon node
type BeaconNode struct {
	genesisTimestamp int64
	secondsPerSlot   uint64
	slotsPerEpoch    uint64
}

// New creates a new mock beacon node connection.
func New() (*BeaconNode, error) {
	return &BeaconNode{
		genesisTimestamp: 1588291200,
		secondsPerSlot:   12,
		slotsPerEpoch:    32,
	}, nil
}

// FetchSecondsPerSlot fetches the number of seconds per slot for the attached beacon node.
func (bn *BeaconNode) FetchSecondsPerSlot() uint64 {
	return bn.secondsPerSlot
}

// FetchSlotsPerEpoch fetches the number of slots per epoch for the attached beacon node.
func (bn *BeaconNode) FetchSlotsPerEpoch() uint64 {
	return bn.slotsPerEpoch
}

// CalcTimestampOfSlot calculates the timestamp of the start of the given slot.
func (bn *BeaconNode) CalcTimestampOfSlot(slot uint64) int64 {
	return bn.genesisTimestamp + int64(slot*bn.secondsPerSlot)
}

// CalcTimestampOfEpoch calculates the timestamp of the start of the given epoch.
func (bn *BeaconNode) CalcTimestampOfEpoch(epoch uint64) int64 {
	return bn.genesisTimestamp + int64(epoch*bn.secondsPerSlot*bn.slotsPerEpoch)
}
