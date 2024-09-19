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

package utils

import apiv1 "github.com/attestantio/go-eth2-client/api/v1"

// IsSyncCommitteeEligible returns true if the validator is in a state that is eligible for Sync Committee duty.
func IsSyncCommitteeEligible(state apiv1.ValidatorState) bool {
	return state == apiv1.ValidatorStateActiveOngoing || state == apiv1.ValidatorStateActiveExiting ||
		state == apiv1.ValidatorStateExitedUnslashed || state == apiv1.ValidatorStateActiveSlashed ||
		state == apiv1.ValidatorStateExitedSlashed || state == apiv1.ValidatorStateWithdrawalPossible
}
