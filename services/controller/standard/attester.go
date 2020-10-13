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

package standard

import (
	"context"
	"fmt"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/attestantio/vouch/services/attester"
)

// createAttesterJobs creates attestation jobs for the given epoch provided accounts.
func (s *Service) createAttesterJobs(ctx context.Context,
	epoch uint64,
	accounts []accountmanager.ValidatingAccount,
	firstRun bool) {
	log.Trace().Msg("Creating attester jobs")

	idProviders := make([]eth2client.ValidatorIDProvider, len(accounts))
	for i, account := range accounts {
		idProviders[i] = account.(eth2client.ValidatorIDProvider)
	}
	resp, err := s.attesterDutiesProvider.AttesterDuties(ctx, epoch, idProviders)
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain attester duties")
		return
	}

	// Filter bad responses.
	filteredDuties := make([]*api.AttesterDuty, 0, len(resp))
	firstSlot := epoch * s.slotsPerEpoch
	lastSlot := (epoch+1)*s.slotsPerEpoch - 1
	for _, duty := range resp {
		if duty.Slot < firstSlot || duty.Slot > lastSlot {
			log.Warn().Uint64("epoch", epoch).Uint64("duty_slot", duty.Slot).Msg("Attester duty has invalid slot for requested epoch; ignoring")
			continue
		}
		filteredDuties = append(filteredDuties, duty)
	}

	duties, err := attester.MergeDuties(ctx, filteredDuties)
	if err != nil {
		log.Error().Err(err).Msg("Failed to merge attester duties")
		return
	}

	for _, duty := range duties {
		log.
			Trace().
			Uint64("slot", duty.Slot()).
			Uints64("committee_indices", duty.CommitteeIndices()).
			Uints64("validator_indices", duty.ValidatorCommitteeIndices()).
			Msg("Received attester duty")
	}

	currentSlot := s.chainTimeService.CurrentSlot()
	for _, duty := range duties {
		// Do not schedule attestations for past slots (or the current slot if we've just started).
		if duty.Slot() < currentSlot {
			log.Debug().Uint64("attestation_slot", duty.Slot()).Uint64("current_slot", currentSlot).Msg("Attestation in the past; not scheduling")
			continue
		}
		if firstRun && duty.Slot() == currentSlot {
			log.Debug().Uint64("attestation_slot", duty.Slot()).Uint64("current_slot", currentSlot).Msg("Attestation in the current slot and this is our first run; not scheduling")
			continue
		}
		if err := s.scheduler.ScheduleJob(ctx,
			fmt.Sprintf("Beacon block attestations for slot %d", duty.Slot()),
			s.chainTimeService.StartOfSlot(duty.Slot()).Add(s.slotDuration/3),
			s.AttestAndScheduleAggregate,
			duty,
		); err != nil {
			// Don't return here; we want to try to set up as many attester jobs as possible.
			log.Error().Err(err).Msg("Failed to set attester job")
		}
	}
}

// AttestAndScheduleAggregate attests, then schedules aggregation jobs as required.
func (s *Service) AttestAndScheduleAggregate(ctx context.Context, data interface{}) {
	duty, ok := data.(*attester.Duty)
	if !ok {
		log.Error().Msg("Passed invalid data")
		return
	}

	attestations, err := s.attester.Attest(ctx, duty)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to attest")
	}

	if len(attestations) == 0 {
		log.Debug().Msg("No attestations; nothing to aggregate")
		return
	}

	epoch := attestations[0].Data.Slot / s.slotsPerEpoch
	s.subscriptionInfosMutex.Lock()
	subscriptionInfoMap, exists := s.subscriptionInfos[epoch]
	s.subscriptionInfosMutex.Unlock()
	if !exists {
		log.Warn().Msg("No subscription info for this epoch; cannot aggregate")
		return
	}

	for _, attestation := range attestations {
		slotInfoMap, exists := subscriptionInfoMap[attestation.Data.Slot]
		if !exists {
			log.Debug().Uint64("attestation_slot", attestation.Data.Slot).Msg("No slot info; cannot aggregate")
			continue
		}
		// Do not schedule aggregations for past slots.
		if attestation.Data.Slot < s.chainTimeService.CurrentSlot() {
			log.Debug().Uint64("aggregation_slot", attestation.Data.Slot).Uint64("current_slot", s.chainTimeService.CurrentSlot()).Msg("Aggregation in the past; not scheduling")
			continue
		}
		info, exists := slotInfoMap[attestation.Data.Index]
		if !exists {
			log.Debug().Uint64("attestation_slot", attestation.Data.Slot).Uint64("committee_index", attestation.Data.Index).Msg("No committee info; cannot aggregate")
			continue
		}
		if info.Aggregate {
			aggregatorDuty, err := attestationaggregator.NewDuty(ctx, info.ValidatorIndex, info.ValidatorPubKey, attestation, info.Signature)
			if err != nil {
				// Don't return here; we want to try to set up as many aggregator jobs as possible.
				log.Error().Err(err).Msg("Failed to create beacon block attestation aggregation duty")
				continue
			}
			if err := s.scheduler.ScheduleJob(ctx,
				fmt.Sprintf("Beacon block attestation aggregation for slot %d committee %d", attestation.Data.Slot, attestation.Data.Index),
				s.chainTimeService.StartOfSlot(attestation.Data.Slot).Add(s.slotDuration*2/3),
				s.attestationAggregator.Aggregate,
				aggregatorDuty,
			); err != nil {
				// Don't return here; we want to try to set up as many aggregator jobs as possible.
				log.Error().Err(err).Msg("Failed to schedule beacon block attestation aggregation job")
				continue
			}
			// We are set up as an aggregator for this slot and committee.  It is possible that another validator has also been
			// assigned as an aggregator, but we're already carrying out the task so do not need to go any further.
			return
		}
	}
}
