// Copyright © 2020, 2022 Attestant Limited.
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

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// scoreAttestationData generates a score for attestation data.
// The score is relative to the reward expected from the contents of the attestation.
func (s *Service) scoreAttestationData(ctx context.Context,
	name string,
	attestationData *phase0.AttestationData,
) float64 {
	if attestationData == nil {
		return 0
	}

	// Initial score is based on height of source and target epochs.
	score := float64(attestationData.Source.Epoch + attestationData.Target.Epoch)

	// Increase score based on the nearness of the head slot.
	slot, err := s.blockRootToSlotCache.BlockRootToSlot(ctx, attestationData.BeaconBlockRoot)
	if err != nil {
		log.Warn().Str("root", fmt.Sprintf("%#x", attestationData.BeaconBlockRoot)).Err(err).Msg("Failed to obtain slot for block root")
		slot = 0
	} else {
		score += float64(1) / float64(1+attestationData.Slot-slot)
	}

	log.Trace().
		Str("provider", name).
		Uint64("attestation_slot", uint64(attestationData.Slot)).
		Uint64("head_slot", uint64(slot)).
		Uint64("source_epoch", uint64(attestationData.Source.Epoch)).
		Uint64("target_epoch", uint64(attestationData.Target.Epoch)).
		Float64("score", score).
		Msg("Scored attestation data")
	return score
}
