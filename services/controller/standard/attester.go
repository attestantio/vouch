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
	"time"

	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/attestantio/vouch/services/attester"
)

// scheduleAttestations schedules attestations for the given epoch and validator indices.
func (s *Service) scheduleAttestations(ctx context.Context,
	epoch phase0.Epoch,
	validatorIndices []phase0.ValidatorIndex,
	notCurrentSlot bool,
) {
	if len(validatorIndices) == 0 {
		// Nothing to do.
		return
	}

	started := time.Now()
	log.Trace().Uint64("epoch", uint64(epoch)).Msg("Scheduling attestations")

	resp, err := s.attesterDutiesProvider.AttesterDuties(ctx, epoch, validatorIndices)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch attester duties")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Int("duties", len(resp)).Msg("Fetched attester duties")

	// Generate Vouch duties from the response.
	filteredDuties := make([]*api.AttesterDuty, 0, len(resp))
	firstSlot := s.chainTimeService.FirstSlotOfEpoch(epoch)
	lastSlot := s.chainTimeService.FirstSlotOfEpoch(epoch+1) - 1
	for _, duty := range resp {
		if duty.Slot < firstSlot || duty.Slot > lastSlot {
			log.Warn().
				Uint64("epoch", uint64(epoch)).
				Uint64("duty_slot", uint64(duty.Slot)).
				Msg("Attester duty has invalid slot for requested epoch; ignoring")
			continue
		}
		filteredDuties = append(filteredDuties, duty)
	}
	log.Trace().Dur("elapsed", time.Since(started)).Int("duties", len(filteredDuties)).Msg("Filtered attester duties")

	duties, err := attester.MergeDuties(ctx, filteredDuties)
	if err != nil {
		log.Error().Err(err).Msg("Failed to merge attester duties")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Int("duties", len(duties)).Msg("Merged attester duties")

	if e := log.Trace(); e.Enabled() {
		for _, duty := range duties {
			log.Trace().
				Uint64("slot", uint64(duty.Slot())).
				Strs("duties", duty.Tuples()).
				Msg("Received attester duties")
		}
	}

	currentSlot := s.chainTimeService.CurrentSlot()
	for _, duty := range duties {
		// Do not schedule attestations for past slots (or the current slot if so instructed).
		if duty.Slot() < currentSlot {
			log.Debug().
				Uint64("attestation_slot", uint64(duty.Slot())).
				Uint64("current_slot", uint64(currentSlot)).
				Msg("Attestation for a past slot; not scheduling")
			continue
		}
		if duty.Slot() == currentSlot && notCurrentSlot {
			log.Debug().
				Uint64("attestation_slot", uint64(duty.Slot())).
				Uint64("current_slot", uint64(currentSlot)).
				Msg("Attestation for the current slot; not scheduling")
			continue
		}
		go func(duty *attester.Duty) {
			jobTime := s.chainTimeService.StartOfSlot(duty.Slot()).Add(s.maxAttestationDelay)
			if err := s.scheduler.ScheduleJob(ctx,
				"Attest",
				fmt.Sprintf("Attestations for slot %d", duty.Slot()),
				jobTime,
				s.AttestAndScheduleAggregate,
				duty,
			); err != nil {
				// Don't return here; we want to try to set up as many attester jobs as possible.
				log.Error().Err(err).Msg("Failed to schedule attestation")
			}
		}(duty)
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Scheduled attestations")
}

// AttestAndScheduleAggregate attests, then schedules aggregation jobs as required.
func (s *Service) AttestAndScheduleAggregate(ctx context.Context, data interface{}) {
	started := time.Now()
	duty, ok := data.(*attester.Duty)
	if !ok {
		log.Error().Msg("Passed invalid data")
		return
	}
	log := log.With().Uint64("slot", uint64(duty.Slot())).Logger()

	attestations, err := s.attester.Attest(ctx, duty)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to attest")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Attested")

	if len(attestations) == 0 || attestations[0].Data == nil {
		log.Debug().Msg("No attestations; nothing to aggregate")
		return
	}

	epoch := s.chainTimeService.SlotToEpoch(duty.Slot())
	s.subscriptionInfosMutex.Lock()
	subscriptionInfoMap, exists := s.subscriptionInfos[epoch]
	s.subscriptionInfosMutex.Unlock()
	if !exists {
		log.Debug().
			Uint64("epoch", uint64(epoch)).
			Msg("No subscription info for this epoch; not aggregating")
		return
	}

	for _, attestation := range attestations {
		log := log.With().Uint64("attestation_slot", uint64(attestation.Data.Slot)).Uint64("committee_index", uint64(attestation.Data.Index)).Logger()
		slotInfoMap, exists := subscriptionInfoMap[attestation.Data.Slot]
		if !exists {
			log.Debug().Msg("No slot info; not aggregating")
			continue
		}
		// Do not schedule aggregations for past slots.
		if attestation.Data.Slot < s.chainTimeService.CurrentSlot() {
			log.Debug().Uint64("current_slot", uint64(s.chainTimeService.CurrentSlot())).Msg("Aggregation in the past; not scheduling")
			continue
		}
		info, exists := slotInfoMap[attestation.Data.Index]
		if !exists {
			log.Debug().Uint64("committee_index", uint64(attestation.Data.Index)).Msg("No committee info; not aggregating")
			continue
		}
		if info.IsAggregator {
			accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, epoch, []phase0.ValidatorIndex{info.Duty.ValidatorIndex})
			if err != nil {
				// Don't return here; we want to try to set up as many aggregator jobs as possible.
				log.Error().Err(err).Msg("Failed to obtain accounts")
				continue
			}
			if len(accounts) == 0 {
				// Don't return here; we want to try to set up as many aggregator jobs as possible.
				log.Error().Msg("Failed to obtain account of attester")
				continue
			}
			attestationDataRoot, err := attestation.Data.HashTreeRoot()
			if err != nil {
				// Don't return here; we want to try to set up as many aggregator jobs as possible.
				log.Error().Err(err).Msg("Failed to obtain hash tree root of attestation")
				continue
			}
			aggregatorDuty := &attestationaggregator.Duty{
				Slot:                info.Duty.Slot,
				AttestationDataRoot: attestationDataRoot,
				ValidatorIndex:      info.Duty.ValidatorIndex,
				SlotSignature:       info.Signature,
			}
			if err := s.scheduler.ScheduleJob(ctx,
				"Aggregate attestations",
				fmt.Sprintf("Beacon block attestation aggregation for slot %d committee %d", attestation.Data.Slot, attestation.Data.Index),
				s.chainTimeService.StartOfSlot(attestation.Data.Slot).Add(s.attestationAggregationDelay),
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
