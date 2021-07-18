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

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
)

// scheduleProposals schedules proposals for the given epoch and validator indices.
func (s *Service) scheduleProposals(ctx context.Context,
	epoch phase0.Epoch,
	validatorIndices []phase0.ValidatorIndex,
	notCurrentSlot bool,
) {
	if len(validatorIndices) == 0 {
		// Nothing to do.
		return
	}

	started := time.Now()
	log.Trace().Uint64("epoch", uint64(epoch)).Msg("Scheduling proposals")

	resp, err := s.proposerDutiesProvider.ProposerDuties(ctx, epoch, validatorIndices)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch proposer duties")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Int("duties", len(resp)).Msg("Fetched proposer duties")

	// Generate Vouch duties from the response.
	duties := make([]*beaconblockproposer.Duty, 0, len(resp))
	firstSlot := s.chainTimeService.FirstSlotOfEpoch(epoch)
	lastSlot := s.chainTimeService.FirstSlotOfEpoch(epoch+1) - 1
	for _, respDuty := range resp {
		if respDuty.Slot < firstSlot || respDuty.Slot > lastSlot {
			log.Warn().
				Uint64("epoch", uint64(epoch)).
				Uint64("duty_slot", uint64(respDuty.Slot)).
				Msg("Proposer duty has invalid slot for requested epoch; ignoring")
			continue
		}
		duties = append(duties, beaconblockproposer.NewDuty(respDuty.Slot, respDuty.ValidatorIndex))
	}
	log.Trace().Dur("elapsed", time.Since(started)).Int("duties", len(duties)).Msg("Filtered proposer duties")

	currentSlot := s.chainTimeService.CurrentSlot()
	for _, duty := range duties {
		// Do not schedule proposals for past slots (or the current slot if so instructed).
		if duty.Slot() < currentSlot {
			log.Debug().
				Uint64("proposal_slot", uint64(duty.Slot())).
				Uint64("current_slot", uint64(currentSlot)).
				Msg("Beacon block proposal for a past slot; not scheduling")
			continue
		}
		if duty.Slot() == currentSlot && notCurrentSlot {
			log.Debug().
				Uint64("proposal_slot", uint64(duty.Slot())).
				Uint64("current_slot", uint64(currentSlot)).
				Msg("Beacon block proposal for the current slot; not scheduling")
			continue
		}
		go func(duty *beaconblockproposer.Duty) {
			if err := s.beaconBlockProposer.Prepare(ctx, duty); err != nil {
				log.Error().Uint64("proposal_slot", uint64(duty.Slot())).Err(err).Msg("Failed to prepare beacon block proposal")
				return
			}
			if err := s.scheduler.ScheduleJob(ctx,
				fmt.Sprintf("Beacon block proposal for slot %d", duty.Slot()),
				s.chainTimeService.StartOfSlot(duty.Slot()),
				s.beaconBlockProposer.Propose,
				duty,
			); err != nil {
				// Don't return here; we want to try to set up as many proposer jobs as possible.
				log.Error().Err(err).Msg("Failed to schedule beacon block proposal")
			}
		}(duty)
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Scheduled beacon block proposals")
}
