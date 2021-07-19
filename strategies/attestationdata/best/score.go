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
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// scoreAttestationData generates a score for attestation data.
// The score is relative to the reward expected by proposing the block.
func (s *Service) scoreAttestationData(ctx context.Context,
	provider eth2client.AttestationDataProvider,
	name string,
	attestationData *phase0.AttestationData,
) float64 {
	if attestationData == nil {
		return 0
	}

	var slot phase0.Slot
	if headerProvider, isProvider := provider.(eth2client.BeaconBlockHeadersProvider); isProvider {
		block, err := headerProvider.BeaconBlockHeader(ctx, fmt.Sprintf("%#x", attestationData.BeaconBlockRoot))
		if err != nil {
			log.Error().Err(err).Msg("Failed to obtain block header")
			return float64(attestationData.Source.Epoch + attestationData.Target.Epoch)
		}
		slot = block.Header.Message.Slot
	} else if blockProvider, isProvider := provider.(eth2client.SignedBeaconBlockProvider); isProvider {
		block, err := blockProvider.SignedBeaconBlock(ctx, fmt.Sprintf("%#x", attestationData.BeaconBlockRoot))
		if err != nil {
			log.Error().Err(err).Msg("Failed to obtain block")
			return float64(attestationData.Source.Epoch + attestationData.Target.Epoch)
		}
		if block == nil {
			log.Warn().Str("block_root", fmt.Sprintf("%#x", attestationData.BeaconBlockRoot)).Msg("No block returned by provider")
			return float64(attestationData.Source.Epoch + attestationData.Target.Epoch)
		}
		if block.Message == nil {
			log.Warn().Str("block_root", fmt.Sprintf("%#x", attestationData.BeaconBlockRoot)).Msg("Empty block returned by provider")
			return float64(attestationData.Source.Epoch + attestationData.Target.Epoch)
		}
		slot = block.Message.Slot
	} else {
		log.Warn().Msg("Cannot score attestation")
		return float64(attestationData.Source.Epoch + attestationData.Target.Epoch)
	}
	score := float64(attestationData.Source.Epoch+attestationData.Target.Epoch) + float64(1)/float64(1+attestationData.Slot-slot)

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
