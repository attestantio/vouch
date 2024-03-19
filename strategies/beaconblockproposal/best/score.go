// Copyright © 2020 - 2024 Attestant Limited.
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
	"math/big"

	"github.com/attestantio/go-eth2-client/api"
)

// scoreBeaconBlockPropsal generates a score for a beacon block.
// The score is the reward expected by proposing the block.
func (s *Service) scoreBeaconBlockProposal(_ context.Context,
	name string,
	blockProposal *api.VersionedProposal,
) float64 {
	if blockProposal == nil {
		return 0
	}

	score, _ := new(big.Int).Add(blockProposal.ConsensusValue, blockProposal.ExecutionValue).Float64()

	log.Trace().
		Str("name", name).
		Stringer("consensus_value", blockProposal.ConsensusValue).
		Stringer("execution_value", blockProposal.ExecutionValue).
		Float64("score", score).
		Msg("Scored block")

	return score
}
