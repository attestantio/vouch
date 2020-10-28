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

	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/beaconblockproposer"
)

// createProposerJobs creates proposal jobs for the given epoch.
func (s *Service) createProposerJobs(ctx context.Context,
	epoch uint64,
	accounts []accountmanager.ValidatingAccount,
	firstRun bool) {
	log.Trace().Msg("Creating proposer jobs")

	validatorIDs := make([]uint64, len(accounts))
	var err error
	for i, account := range accounts {
		validatorIDs[i], err = account.Index(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Failed to obtain account index")
			return
		}
	}

	resp, err := s.proposerDutiesProvider.ProposerDuties(ctx, epoch, validatorIDs)
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain proposer duties")
		return
	}

	// Filter bad responses.
	duties := make([]*beaconblockproposer.Duty, 0, len(resp))
	firstSlot := epoch * s.slotsPerEpoch
	lastSlot := (epoch+1)*s.slotsPerEpoch - 1
	for _, respDuty := range resp {
		if respDuty.Slot < firstSlot || respDuty.Slot > lastSlot {
			log.Warn().Uint64("epoch", epoch).Uint64("duty_slot", respDuty.Slot).Msg("Proposer duty has invalid slot for requested epoch; ignoring")
			continue
		}
		duty, err := beaconblockproposer.NewDuty(ctx, respDuty.Slot, respDuty.ValidatorIndex)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create proposer duty")
			continue
		}
		duties = append(duties, duty)
	}

	currentSlot := s.chainTimeService.CurrentSlot()
	for _, duty := range duties {
		// Do not schedule proposals for past slots (or the current slot if we've just started).
		if duty.Slot() < currentSlot || firstRun && duty.Slot() == currentSlot {
			log.Debug().Uint64("proposal_slot", duty.Slot()).Uint64("current_slot", currentSlot).Msg("Proposal in the past; not scheduling")
			continue
		}
		go func(duty *beaconblockproposer.Duty) {
			if err := s.beaconBlockProposer.Prepare(ctx, duty); err != nil {
				log.Error().Uint64("proposal_slot", duty.Slot()).Err(err).Msg("Failed to prepare proposal")
				return
			}
			if err := s.scheduler.ScheduleJob(ctx,
				fmt.Sprintf("Beacon block proposal for slot %d", duty.Slot()),
				s.chainTimeService.StartOfSlot(duty.Slot()),
				s.beaconBlockProposer.Propose,
				duty,
			); err != nil {
				// Don't return here; we want to try to set up as many proposer jobs as possible.
				log.Error().Err(err).Msg("Failed to set proposer job")
			}
		}(duty)
	}
}
