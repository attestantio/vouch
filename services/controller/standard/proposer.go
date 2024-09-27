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

package standard

import (
	"context"
	"fmt"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/util"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
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
	s.log.Trace().Uint64("epoch", uint64(epoch)).Msg("Scheduling proposals")

	proposerDutiesResponse, err := s.proposerDutiesProvider.ProposerDuties(ctx, &api.ProposerDutiesOpts{
		Epoch:   epoch,
		Indices: validatorIndices,
	})
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to fetch proposer duties")
		return
	}
	proposerDuties := proposerDutiesResponse.Data
	s.log.Trace().Dur("elapsed", time.Since(started)).Int("duties", len(proposerDuties)).Msg("Fetched proposer duties")

	// Generate Vouch duties from the response.
	duties := make([]*beaconblockproposer.Duty, 0, len(proposerDuties))
	firstSlot := s.chainTimeService.FirstSlotOfEpoch(epoch)
	lastSlot := s.chainTimeService.FirstSlotOfEpoch(epoch+1) - 1
	for _, respDuty := range proposerDuties {
		if respDuty.Slot < firstSlot || respDuty.Slot > lastSlot {
			s.log.Warn().
				Uint64("epoch", uint64(epoch)).
				Uint64("duty_slot", uint64(respDuty.Slot)).
				Msg("Proposer duty has invalid slot for requested epoch; ignoring")
			continue
		}
		duties = append(duties, beaconblockproposer.NewDuty(respDuty.Slot, respDuty.ValidatorIndex))
	}
	s.log.Trace().Dur("elapsed", time.Since(started)).Int("duties", len(duties)).Msg("Filtered proposer duties")

	currentSlot := s.chainTimeService.CurrentSlot()
	for _, duty := range duties {
		// Do not schedule proposals for past slots (or the current slot if so instructed).
		if duty.Slot() < currentSlot {
			s.log.Debug().
				Uint64("proposal_slot", uint64(duty.Slot())).
				Uint64("current_slot", uint64(currentSlot)).
				Msg("Beacon block proposal for a past slot; not scheduling")
			continue
		}
		if duty.Slot() == currentSlot && notCurrentSlot {
			s.log.Debug().
				Uint64("proposal_slot", uint64(duty.Slot())).
				Uint64("current_slot", uint64(currentSlot)).
				Msg("Beacon block proposal for the current slot; not scheduling")
			continue
		}
		go func(duty *beaconblockproposer.Duty) {
			if err := s.beaconBlockProposer.Prepare(ctx, duty); err != nil {
				s.log.Error().Uint64("proposal_slot", uint64(duty.Slot())).Err(err).Msg("Failed to prepare beacon block proposal")
				return
			}
			// Only bother trying to propose early if the alternative is later.
			if s.maxProposalDelay > 0 {
				if err := s.scheduler.ScheduleJob(ctx,
					"Propose check",
					fmt.Sprintf("Early beacon block proposal for slot %d", duty.Slot()),
					s.chainTimeService.StartOfSlot(duty.Slot()),
					func(ctx context.Context) { s.proposeEarly(ctx, duty) },
				); err != nil {
					// Don't return here; we want to try to set up as many proposer jobs as possible.
					s.log.Error().Err(err).Msg("Failed to schedule early beacon block proposal")
				}
			}
			if err := s.scheduler.ScheduleJob(ctx,
				"Propose",
				fmt.Sprintf("Beacon block proposal for slot %d", duty.Slot()),
				s.chainTimeService.StartOfSlot(duty.Slot()).Add(s.maxProposalDelay),
				func(ctx context.Context) { s.beaconBlockProposer.Propose(ctx, duty) },
			); err != nil {
				// Don't return here; we want to try to set up as many proposer jobs as possible.
				s.log.Error().Err(err).Msg("Failed to schedule beacon block proposal")
			}
		}(duty)
	}
	s.log.Trace().Dur("elapsed", time.Since(started)).Msg("Scheduled beacon block proposals")
}

// proposeEarly attempts to propose as soon as the slot starts, as long
// as the head of the chain is up-to-date.
func (s *Service) proposeEarly(ctx context.Context, duty *beaconblockproposer.Duty) {
	ctx, span := otel.Tracer("attestantio.vouch.services.controller.standard").Start(ctx, "proposeEarly")
	defer span.End()

	span.SetAttributes(attribute.Int64("slot", util.SlotToInt64(duty.Slot())))

	// Start off by fetching the current head.
	headerResponse, err := s.beaconBlockHeadersProvider.BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{
		Block: "head",
	})
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to obtain beacon block header")
		return
	}
	header := headerResponse.Data

	// If the current head is up to the prior slot then we can propose immediately.
	if header.Header.Message.Slot == duty.Slot()-1 {
		s.log.Trace().Uint64("slot", uint64(duty.Slot())).Uint64("header_slot", uint64(header.Header.Message.Slot)).Uint64("validator_index", uint64(duty.ValidatorIndex())).Str("header", header.String()).Msg("Head of chain is up to date; proposing immediately")
		s.scheduler.RunJobIfExists(ctx, fmt.Sprintf("Beacon block proposal for slot %d", duty.Slot()))
	} else {
		s.log.Trace().Uint64("slot", uint64(duty.Slot())).Uint64("header_slot", uint64(header.Header.Message.Slot)).Uint64("validator_index", uint64(duty.ValidatorIndex())).Str("header", header.String()).Msg("Head of chain is not up to date; not proposing immediately")
	}
}
