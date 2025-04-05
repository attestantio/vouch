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

package staticdelay

import (
	"context"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/vouch/services/attester"
)

// ShouldAttest returns true if this Vouch instance should attest.
func (s *Service) ShouldAttest(ctx context.Context, duty *attester.Duty) bool {
	if duty == nil || len(duty.ValidatorIndices()) == 0 {
		s.log.Debug().Msg("No duty supplied")

		return false
	}

	log := s.log.With().Uint64("slot", uint64(duty.Slot())).Logger()
	log.Trace().Msg("Checking if we should attest")

	if s.attesterActive.Load() {
		log.Trace().Msg("We are the active attester")
		s.enableAttester(ctx)

		return true
	}

	// Sleep to let other instances do their work.
	time.Sleep(s.attesterDelay)

	slot := duty.Slot()
	committeeIndex := duty.CommitteeIndices()[0]
	validatorCommitteeIndex := duty.ValidatorCommitteeIndices()[0]
	resp, err := s.attestationPoolProvider.AttestationPool(ctx, &api.AttestationPoolOpts{
		Slot:           &slot,
		CommitteeIndex: &committeeIndex,
	})
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain attester duties; activating attester")
		s.enableAttester(ctx)

		return true
	}

	for _, attestation := range resp.Data {
		if attestation.AggregationBits.BitAt(validatorCommitteeIndex) {
			// An attestation is already in the pool; we don't need to act.
			log.Trace().Msg("Another instance is attesting; not activating attester")
			s.disableAttester(ctx)

			return false
		}
	}

	log.Trace().Msg("No attestation found; activating attester")
	s.enableAttester(ctx)

	return true
}
