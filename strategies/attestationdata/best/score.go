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
	"fmt"

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
)

// scoreAttestationData generates a score for attestation data.
// The score is relative to the reward expected by proposing the block.
func (s *Service) scoreAttestationData(ctx context.Context,
	provider eth2client.AttestationDataProvider,
	name string,
	attestationData *spec.AttestationData,
) float64 {
	if attestationData == nil {
		return 0
	}

	var slot spec.Slot
	if headerProvider, isProvider := provider.(eth2client.BeaconBlockHeadersProvider); isProvider {
		block, err := headerProvider.BeaconBlockHeader(ctx, fmt.Sprintf("%#x", attestationData.BeaconBlockRoot))
		if err != nil {
			log.Error().Err(err).Msg("failed to obtain block header")
			return float64(1) / float64(32)
		}
		slot = block.Header.Message.Slot
	} else if blockProvider, isProvider := provider.(eth2client.SignedBeaconBlockProvider); isProvider {
		block, err := blockProvider.SignedBeaconBlock(ctx, fmt.Sprintf("%#x", attestationData.BeaconBlockRoot))
		if err != nil {
			log.Error().Err(err).Msg("failed to obtain block")
			return float64(1) / float64(32)
		}
		slot = block.Message.Slot
	} else {
		log.Warn().Msg("Cannot score attestation")
		// Give minimal score.
		slot = attestationData.Slot - 32
	}
	score := float64(1) / float64(1+attestationData.Slot-slot)

	log.Trace().
		Str("provider", name).
		Uint64("attestation_slot", uint64(attestationData.Slot)).
		Uint64("head_slot", uint64(slot)).
		Float64("score", score).
		Msg("Scored attestation data")
	return score
}
