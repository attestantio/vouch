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

package beaconblockproposer

// BeaconBlockProposerDuty contains information about a beacon block proposal.
type BeaconBlockProposerDuty interface {
	Slot() uint64
	PublicKey() []byte
}

// BeaconBlockProposer defines an interface that proposes blocks.
type Proposer interface {
	// Schedule passes a proposer schedule.
	Schedule([]*BeaconBlockProposerDuty)
}
