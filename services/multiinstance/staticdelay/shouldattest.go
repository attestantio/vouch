// Copyright © 2024, 2025 Attestant Limited.
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
	"github.com/attestantio/go-eth2-client/spec/phase0"
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
	// Start off by sleeping until 4 seconds into the slot.
	time.Sleep(time.Until(s.chainTime.StartOfSlot(duty.Slot()).Add(s.specAttestationDelay)))
	// Now sleep for the additional attester delay.
	time.Sleep(s.attesterDelay)
	log.Trace().Msg("Checking for attestations from an active instance")

	// Look for any attestations that we are meant to generate that are already in the node's attestation pool.
	slot := duty.Slot()

	// Turn the duty information into maps for easy lookup.
	// Map is committee index -> validator offset in committee.
	committeesMap := make(map[phase0.CommitteeIndex]map[uint64]phase0.ValidatorIndex)
	for i, validatorIndex := range duty.ValidatorIndices() {
		committeeIndex := duty.CommitteeIndices()[i]
		validatorCommitteeIndex := duty.ValidatorCommitteeIndices()[i]
		if _, exists := committeesMap[committeeIndex]; !exists {
			committeesMap[committeeIndex] = make(map[uint64]phase0.ValidatorIndex)
		}
		committeesMap[committeeIndex][validatorCommitteeIndex] = validatorIndex
	}

	// Go through the committee indices one at a time, to avoid overloading ourselves with attestations from the pool, and because
	// we expect to find attestations in all committees if the network is behaving so don't pull data unnecessarily.
	for committeeIndex, dutyAttestations := range committeesMap {
		resp, err := s.attestationPoolProvider.AttestationPool(ctx, &api.AttestationPoolOpts{
			Slot:           &slot,
			CommitteeIndex: &committeeIndex,
		})
		if err != nil {
			log.Warn().Err(err).Msg("Failed to obtain attestation pool")
			continue
		}

		for _, attestation := range resp.Data {
			// We only accept single-committee attestations.
			if _, err := attestation.CommitteeIndex(); err != nil {
				continue
			}

			aggregationBits, err := attestation.AggregationBits()
			if err != nil {
				log.Warn().Err(err).Msg("Failed to obtain aggregation bits")
				continue
			}
			for validatorCommitteeIndex := range dutyAttestations {
				if aggregationBits.BitAt(validatorCommitteeIndex) {
					// An attestation is already in the pool; we don't need to act.
					log.Trace().Msg("Another instance is attesting; not activating attester")
					s.disableAttester(ctx)

					return false
				}
			}
		}
	}

	log.Trace().Msg("No attestation found; activating attester")
	s.enableAttester(ctx)

	return true
}
