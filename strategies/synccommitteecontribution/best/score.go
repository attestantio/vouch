// Copyright © 2021 Attestant Limited.
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

	"github.com/attestantio/go-eth2-client/spec/altair"
)

// scoreSyncCommitteeContribution generates a score for an aggregate attestation.
// The score is relative to the completeness of the aggregate.
// skipcq: RVV-B0012
func (*Service) scoreSyncCommitteeContribution(ctx context.Context,
	name string,
	contribution *altair.SyncCommitteeContribution,
) float64 {
	if contribution == nil {
		return 0
	}

	score := float64(contribution.AggregationBits.Count())

	log.Trace().
		Str("provider", name).
		Uint64("sync_committee_slot", uint64(contribution.Slot)).
		Uint64("subcommittee_index", contribution.SubcommitteeIndex).
		Str("beacon_block_root", fmt.Sprintf("%#x", contribution.BeaconBlockRoot)).
		Float64("score", score).
		Msg("Scored sync committee contribution")
	return score
}
