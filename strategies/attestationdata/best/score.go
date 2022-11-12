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

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
)

// scoreAttestationData generates a score for attestation data.
// The score is relative to the reward expected by proposing the block.
func (s *Service) scoreAttestationData(ctx context.Context, name string, attestationData *spec.AttestationData) float64 {
	if attestationData == nil {
		return 0
	}

	//	log.Trace().
	//		Uint64("slot", blockProposal.Slot).
	//		Str("provider", name).
	//		Float64("immediate_attestations", immediateAttestationScore).
	//		Float64("attestations", attestationScore).
	//		Float64("proposer_slashings", proposerSlashingScore).
	//		Float64("attester_slashings", attesterSlashingScore).
	//		Float64("total", attestationScore+proposerSlashingScore+attesterSlashingScore).
	//		Msg("Scored block")
	//
	//	return attestationScore + proposerSlashingScore + attesterSlashingScore
	return 0
}
