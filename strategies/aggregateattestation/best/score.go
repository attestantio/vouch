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

package best

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// scoreAggregateAttestation generates a score for an aggregate attestation.
// The score is relative to the completeness of the aggregate.
func (*Service) scoreAggregateAttestation(_ context.Context,
	name string,
	aggregate *phase0.Attestation,
) float64 {
	if aggregate == nil {
		return 0
	}

	included := 0
	total := aggregate.AggregationBits.Len()
	for i := range total {
		if aggregate.AggregationBits.BitAt(i) {
			included++
		}
	}
	score := float64(included) / float64(total)

	log.Trace().
		Str("provider", name).
		Uint64("attestation_slot", uint64(aggregate.Data.Slot)).
		Float64("score", score).
		Msg("Scored aggregate attestation")
	return score
}
