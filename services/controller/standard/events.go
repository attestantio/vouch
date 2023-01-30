// Copyright © 2020, 2021 Attestant Limited.
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
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// HandleBlockEvent handles the "block" events from the beacon node.
func (s *Service) HandleBlockEvent(event *api.Event) {
	if event.Data == nil {
		return
	}

	data := event.Data.(*api.BlockEvent)
	// We update the block to slot cache here, in an attempt to avoid
	// unnecessary lookups.
	s.blockToSlotSetter.SetBlockRootToSlot(data.Block, data.Slot)
}

// HandleHeadEvent handles the "head" events from the beacon node.
func (s *Service) HandleHeadEvent(event *api.Event) {
	ctx, span := otel.Tracer("attestantio.vouch.services.controller.standard").Start(context.Background(), "HandleHeadEvent")
	defer span.End()

	if event.Data == nil {
		return
	}

	var zeroRoot phase0.Root

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
	epoch := s.chainTimeService.SlotToEpoch(data.Slot)

	s.monitor.BlockDelay(uint(uint64(data.Slot)%s.slotsPerEpoch), time.Since(s.chainTimeService.StartOfSlot(data.Slot)))

	// If this block is for the prior slot and we may have a proposal waiting then kick
	// off any proposal for this slot.
	if data.Slot == s.chainTimeService.CurrentSlot()-1 && s.maxProposalDelay > 0 {
		proposalJobName := fmt.Sprintf("Beacon block proposal for slot %d", s.chainTimeService.CurrentSlot())
		if s.scheduler.JobExists(ctx, proposalJobName) {
			log.Trace().Msg("Kicking off proposal for slot now that parent block for last slot has arrived")
			s.scheduler.RunJobIfExists(ctx, proposalJobName)
		}
	}

	// Check to see if there is a reorganisation that requires re-fetching duties.
	if s.reorgs && s.lastBlockEpoch != 0 {
		if epoch > s.lastBlockEpoch {
			log.Trace().
				Str("old_previous_dependent_root", fmt.Sprintf("%#x", s.previousDutyDependentRoot)).
				Str("new_previous_dependent_root", fmt.Sprintf("%#x", data.PreviousDutyDependentRoot)).
				Str("old_current_dependent_root", fmt.Sprintf("%#x", s.currentDutyDependentRoot)).
				Str("new_current_dependent_root", fmt.Sprintf("%#x", data.CurrentDutyDependentRoot)).
				Msg("Change of epoch")
			// Change of epoch.  Ensure that the new previous dependent root is the same as
			// the old current root.
			if !bytes.Equal(s.previousDutyDependentRoot[:], zeroRoot[:]) &&
				!bytes.Equal(s.currentDutyDependentRoot[:], data.PreviousDutyDependentRoot[:]) {
				log.Debug().
					Str("old_current_dependent_root", fmt.Sprintf("%#x", s.currentDutyDependentRoot[:])).
					Str("new_previous_dependent_root", fmt.Sprintf("%#x", data.PreviousDutyDependentRoot[:])).
					Msg("Previous duty dependent root has changed on epoch transition")
				go s.handlePreviousDependentRootChanged(ctx)
			}
		} else {
			// Existing epoch.  Ensure that the roots are the same.
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
	s.lastBlockEpoch = epoch
	s.previousDutyDependentRoot = data.PreviousDutyDependentRoot
	s.currentDutyDependentRoot = data.CurrentDutyDependentRoot

	// We give the block some time to propagate around the rest of the
	// nodes before kicking off attestations for the block's slot.
	time.Sleep(200 * time.Millisecond)
	jobName := fmt.Sprintf("Attestations for slot %d", data.Slot)
	if s.scheduler.JobExists(ctx, jobName) {
		log.Trace().Msg("Kicking off attestations for slot early due to receiving relevant block")
		s.scheduler.RunJobIfExists(ctx, jobName)
	}
	jobName = fmt.Sprintf("Sync committee messages for slot %d", data.Slot)
	if s.scheduler.JobExists(ctx, jobName) {
		log.Trace().Msg("Kicking off sync committee contributions for slot early due to receiving relevant block")
		s.scheduler.RunJobIfExists(ctx, jobName)
	}

	// Remove old subscriptions if present.
	delete(s.subscriptionInfos, s.chainTimeService.SlotToEpoch(data.Slot)-2)
}

// handlePreviousDependentRootChanged handles the situation where the previous
// dependent root changed.
func (s *Service) handlePreviousDependentRootChanged(ctx context.Context) {
	// Refreshes run in parallel.

	// We need to refresh the attester duties for this epoch.
	go s.refreshAttesterDutiesForEpoch(ctx, s.chainTimeService.CurrentEpoch())
}

// handlePreviousDependentRootChanged handles the situation where the current
// dependent root changed.
func (s *Service) handleCurrentDependentRootChanged(ctx context.Context) {
	// Refreshes run in parallel.

	// We need to refresh the proposer duties for this epoch.
	go s.refreshProposerDutiesForEpoch(ctx, s.chainTimeService.CurrentEpoch())
	// We need to refresh the sync committee duties for the next period if we are
	// at the appropriate boundary.
	if uint64(s.chainTimeService.CurrentEpoch())%s.epochsPerSyncCommitteePeriod == 0 {
		go s.refreshSyncCommitteeDutiesForEpochPeriod(ctx, s.chainTimeService.CurrentEpoch()+phase0.Epoch(s.epochsPerSyncCommitteePeriod))
	}
	// We need to refresh the attester duties for the next epoch.
	go s.refreshAttesterDutiesForEpoch(ctx, s.chainTimeService.CurrentEpoch()+1)
}

func (s *Service) refreshProposerDutiesForEpoch(ctx context.Context, epoch phase0.Epoch) {
	ctx, span := otel.Tracer("attestantio.vouch.services.controller.standard").Start(ctx, "refreshProposerDutiesForEpoch", trace.WithAttributes(
		attribute.Int64("epoch", int64(epoch)),
	))
	defer span.End()

	// First thing we do is cancel all scheduled beacon bock proposal jobs for the epoch.
	for slot := s.chainTimeService.FirstSlotOfEpoch(epoch); slot < s.chainTimeService.FirstSlotOfEpoch(epoch+1); slot++ {
		s.scheduler.CancelJobIfExists(ctx, fmt.Sprintf("Early beacon block proposal for slot %d", slot))
		s.scheduler.CancelJobIfExists(ctx, fmt.Sprintf("Beacon block proposal for slot %d", slot))
	}

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

func (s *Service) refreshAttesterDutiesForEpoch(ctx context.Context, epoch phase0.Epoch) {
	ctx, span := otel.Tracer("attestantio.vouch.services.controller.standard").Start(ctx, "refreshAttesterDutiesForEpoch", trace.WithAttributes(
		attribute.Int64("epoch", int64(epoch)),
	))
	defer span.End()

	// If the epoch duties are yet to be scheduled then we don't have anything to do.
	if s.scheduler.JobExists(ctx, fmt.Sprintf("Prepare for epoch %d", epoch)) {
		log.Trace().Msg("Refresh not necessary as epoch not yet prepared")
		return
	}

	cancelledJobs := make(map[phase0.Slot]bool)
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

// refreshSyncCommitteeDutiesForEpochPeriod refreshes sync committee duties for all epochs in the
// given sync period.
func (s *Service) refreshSyncCommitteeDutiesForEpochPeriod(ctx context.Context, epoch phase0.Epoch) {
	ctx, span := otel.Tracer("attestantio.vouch.services.controller.standard").Start(ctx, "refreshSyncCommitteeDutiesForEpochPeriod", trace.WithAttributes(
		attribute.Int64("epoch", int64(epoch)),
	))
	defer span.End()

	if !s.handlingAltair {
		// Not handling Altair, nothing to do.
		return
	}

	// Work out start and end epoch for the period.
	period := uint64(epoch) / s.epochsPerSyncCommitteePeriod
	firstEpoch := s.firstEpochOfSyncPeriod(period)
	// If we are in the sync committee that starts at slot x we need to generate a message during slot x-1
	// for it to be included in slot x, hence -1.
	firstSlot := s.chainTimeService.FirstSlotOfEpoch(firstEpoch) - 1
	lastEpoch := s.firstEpochOfSyncPeriod(period+1) - 1
	// If we are in the sync committee that ends at slot x we do not generate a message during slot x-1
	// as it will never be included, hence -1.
	lastSlot := s.chainTimeService.FirstSlotOfEpoch(lastEpoch+1) - 2

	// First thing we do is cancel all scheduled sync committee message jobs.
	for slot := firstSlot; slot <= lastSlot; slot++ {
		prepareJobName := fmt.Sprintf("Prepare sync committee messages for slot %d", slot)
		if err := s.scheduler.CancelJob(ctx, prepareJobName); err != nil {
			log.Debug().Str("job_name", prepareJobName).Err(err).Msg("Failed to cancel prepare sync committee message job")
		}
		messageJobName := fmt.Sprintf("Sync committee messages for slot %d", slot)
		if err := s.scheduler.CancelJob(ctx, messageJobName); err != nil {
			log.Debug().Str("job_name", messageJobName).Err(err).Msg("Failed to cancel sync committee message job")
		}
		aggregateJobName := fmt.Sprintf("Sync committee aggregation for slot %d", slot)
		if err := s.scheduler.CancelJob(ctx, aggregateJobName); err != nil {
			log.Debug().Str("job_name", aggregateJobName).Err(err).Msg("Failed to cancel sync committee aggregate job")
		}
	}

	_, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, firstEpoch)
	if err != nil {
		log.Error().Err(err).Uint64("epoch", uint64(firstEpoch)).Msg("Failed to obtain active validators for epoch")
		return
	}

	// Expect at least one validator.
	if len(validatorIndices) == 0 {
		log.Warn().Msg("No active validators; not validating")
		return
	}

	// Reschedule sync committee messages.
	go s.scheduleSyncCommitteeMessages(ctx, epoch, validatorIndices, false /* notCurrentSlot */)
}
