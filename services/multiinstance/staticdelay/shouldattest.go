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
	"slices"
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

	// Look for any attestations that we are meant to generate that are already in the node's attestation pool.
	slot := duty.Slot()
	// Go through the committee indices one at a time, to avoid overloading ourselves with attestations from the pool, and because
	// we expect to find attestations in all committees if the network is behaving so don't pull data unnecessarily.
	for _, committeeIndex := range duty.CommitteeIndices() {
		log.Info().Uint64("slot", uint64(slot)).Uint64("committee_index", uint64(committeeIndex)).Msg("Checking committee for existing attestations")
		validatorCommitteeIndices := duty.ValidatorCommitteeIndices()
		resp, err := s.attestationPoolProvider.AttestationPool(ctx, &api.AttestationPoolOpts{
			Slot:           &slot,
			CommitteeIndex: &committeeIndex,
		})
		if err != nil {
			log.Warn().Err(err).Msg("Failed to obtain attestation pool")
			continue
		}

		for _, attestation := range resp.Data {
			if slices.ContainsFunc(validatorCommitteeIndices, func(index uint64) bool { return attestation.AggregationBits.BitAt(index) }) {
				// An attestation is already in the pool; we don't need to act.
				log.Trace().Msg("Another instance is attesting; not activating attester")
				s.disableAttester(ctx)

				return false
			}
		}
	}

	log.Trace().Msg("No attestation found; activating attester")
	s.enableAttester(ctx)

	return true
}
