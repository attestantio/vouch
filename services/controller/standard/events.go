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
	"bytes"
	"context"
	"fmt"
	"time"

	api "github.com/attestantio/go-eth2-client/api/v1"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
)

// HandleHeadEvent handles the "head" events from the beacon node.
func (s *Service) HandleHeadEvent(event *api.Event) {
	if event.Data == nil {
		return
	}

	ctx := context.Background()
	var zeroRoot spec.Root

	data := event.Data.(*api.HeadEvent)
	log := log.With().Uint64("slot", uint64(data.Slot)).Logger()
	log.Trace().Msg("Received head event")

	if data.Slot != s.chainTimeService.CurrentSlot() {
		return
	}

	// Old versions of teku send a synthetic head event when they don't receive a block
	// by a certain time after start of the slot.  We only care about real block updates
	// for the purposes of this function, so ignore them.
	if !bytes.Equal(s.lastBlockRoot[:], zeroRoot[:]) &&
		bytes.Equal(s.lastBlockRoot[:], data.Block[:]) {
		log.Trace().Msg("Synthetic head event; ignoring")
		return
	}
	s.lastBlockRoot = data.Block

	epochSlot := uint(uint64(data.Slot) % s.slotsPerEpoch)
	s.monitor.BlockDelay(epochSlot, time.Since(s.chainTimeService.StartOfSlot(data.Slot)))

	// Check to see if there is a change in duties.  Note that if this is the first slot
	// in the epoch we expect to see different dependent roots anyway, and updated duties
	// are fetched from the epoch ticker so we don't re-fetch them here.
	if s.reorgs {
		if epochSlot != 0 {
			if !bytes.Equal(s.previousDutyDependentRoot[:], zeroRoot[:]) &&
				!bytes.Equal(s.previousDutyDependentRoot[:], data.PreviousDutyDependentRoot[:]) {
				log.Debug().
					Str("old_dependent_root", fmt.Sprintf("%#x", s.previousDutyDependentRoot[:])).
					Str("new_dependent_root", fmt.Sprintf("%#x", data.PreviousDutyDependentRoot[:])).
					Msg("Previous duty dependent root has changed")
				go s.handlePreviousDependentRootChanged(ctx)
			}

			if !bytes.Equal(s.currentDutyDependentRoot[:], zeroRoot[:]) &&
				!bytes.Equal(s.currentDutyDependentRoot[:], data.CurrentDutyDependentRoot[:]) {
				log.Debug().
					Str("old_dependent_root", fmt.Sprintf("%#x", s.currentDutyDependentRoot[:])).
					Str("new_dependent_root", fmt.Sprintf("%#x", data.CurrentDutyDependentRoot[:])).
					Msg("Current duty dependent root has changed")
				go s.handleCurrentDependentRootChanged(ctx)
			}
		}
	}
	s.previousDutyDependentRoot = data.PreviousDutyDependentRoot
	s.currentDutyDependentRoot = data.CurrentDutyDependentRoot

	// We give the block half a second to propagate around the rest of the
	// network before kicking off attestations for the block's slot.
	time.Sleep(500 * time.Millisecond)
	jobName := fmt.Sprintf("Attestations for slot %d", data.Slot)
	if s.scheduler.JobExists(ctx, jobName) {
		log.Trace().Msg("Kicking off attestations for slot early due to receiving relevant block")
		s.scheduler.RunJobIfExists(ctx, jobName)
	}

	// Remove old subscriptions if present.
	delete(s.subscriptionInfos, s.chainTimeService.SlotToEpoch(data.Slot)-2)
}

// handlePreviousDependentRootChanged handles the situation where the previous
// dependent root changed.
func (s *Service) handlePreviousDependentRootChanged(ctx context.Context) {
	// We need to refresh the attester duties for this epoch.
	s.refreshAttesterDutiesForEpoch(ctx, s.chainTimeService.CurrentEpoch())
}

// handlePreviousDependentRootChanged handles the situation where the current
// dependent root changed.
func (s *Service) handleCurrentDependentRootChanged(ctx context.Context) {
	// We need to refresh the proposer duties for this epoch.
	s.refreshProposerDutiesForEpoch(ctx, s.chainTimeService.CurrentEpoch())
	// We need to refresh the attester duties for the next epoch.
	s.refreshAttesterDutiesForEpoch(ctx, s.chainTimeService.CurrentEpoch()+1)
}

func (s *Service) refreshProposerDutiesForEpoch(ctx context.Context, epoch spec.Epoch) {
	// First thing we do is cancel all scheduled beacon bock proposal jobs.
	s.scheduler.CancelJobs(ctx, "Beacon block proposal")

	_, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, epoch)
	if err != nil {
		log.Error().Err(err).Uint64("epoch", uint64(epoch)).Msg("Failed to obtain active validators for epoch")
		return
	}

	// Expect at least one validator.
	if len(validatorIndices) == 0 {
		log.Warn().Msg("No active validators; not validating")
		return
	}

	s.scheduleProposals(ctx, epoch, validatorIndices, true /* notCurrentSlot */)
}

func (s *Service) refreshAttesterDutiesForEpoch(ctx context.Context, epoch spec.Epoch) {
	cancelledJobs := make(map[spec.Slot]bool)
	// First thing we do is cancel all scheduled attestations jobs.
	for slot := s.chainTimeService.FirstSlotOfEpoch(epoch); slot < s.chainTimeService.FirstSlotOfEpoch(epoch+1); slot++ {
		if err := s.scheduler.CancelJob(ctx, fmt.Sprintf("Attestations for slot %d", slot)); err == nil {
			cancelledJobs[slot] = true
		}
	}

	accounts, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, epoch)
	if err != nil {
		log.Error().Err(err).Uint64("epoch", uint64(epoch)).Msg("Failed to obtain active validators for epoch")
		return
	}

	// Expect at least one validator.
	if len(validatorIndices) == 0 {
		log.Warn().Msg("No active validators; not validating")
		return
	}

	// Reschedule attestations.
	// Only reschedule current slot if its job was cancelled.
	curentSlotJobCancelled := cancelledJobs[s.chainTimeService.CurrentSlot()]
	go s.scheduleAttestations(ctx, epoch, validatorIndices, !curentSlotJobCancelled)

	// Update beacon committee subscriptions for the next epoch.
	subscriptionInfo, err := s.beaconCommitteeSubscriber.Subscribe(ctx, epoch, accounts)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to subscribe to beacon committees")
		return
	}
	s.subscriptionInfosMutex.Lock()
	s.subscriptionInfos[epoch] = subscriptionInfo
	s.subscriptionInfosMutex.Unlock()
}
