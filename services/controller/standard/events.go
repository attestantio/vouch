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
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// HandleBlockEvent handles the "block" events from the beacon node.
func (s *Service) HandleBlockEvent(event *apiv1.Event) {
	if event.Data == nil {
		return
	}

	data := event.Data.(*apiv1.BlockEvent)
	// We update the block to slot cache here, in an attempt to avoid
	// unnecessary lookups.
	s.blockToSlotSetter.SetBlockRootToSlot(data.Block, data.Slot)
}

// HandleHeadEvent handles the "head" events from the beacon node.
func (s *Service) HandleHeadEvent(event *apiv1.Event) {
	ctx, span := otel.Tracer("attestantio.vouch.services.controller.standard").Start(context.Background(), "HandleHeadEvent")
	defer span.End()

	if event.Data == nil {
		return
	}

	data := event.Data.(*apiv1.HeadEvent)
	s.log.Trace().Uint64("slot", uint64(data.Slot)).Msg("Received head event")

	if data.Slot != s.chainTimeService.CurrentSlot() {
		return
	}

	s.lastBlockRoot = data.Block
	epoch := s.chainTimeService.SlotToEpoch(data.Slot)

	monitorBlockDelay(uint(uint64(data.Slot)%s.slotsPerEpoch), time.Since(s.chainTimeService.StartOfSlot(data.Slot)))

	// If this block is for the prior slot and we may have a proposal waiting then kick
	// off any proposal for this slot.
	if data.Slot == s.chainTimeService.CurrentSlot()-1 && s.maxProposalDelay > 0 {
		proposalJobName := fmt.Sprintf("Beacon block proposal for slot %d", s.chainTimeService.CurrentSlot())
		if s.scheduler.JobExists(ctx, proposalJobName) {
			s.log.Trace().Uint64("slot", uint64(data.Slot)).Msg("Kicking off proposal for slot now that parent block for last slot has arrived")
			s.scheduler.RunJobIfExists(ctx, proposalJobName)
		}
	}

	s.checkEventForReorg(ctx, epoch, data.Slot, data.PreviousDutyDependentRoot, data.CurrentDutyDependentRoot)

	s.fastTrackJobs(ctx, data.Slot)

	// Remove old subscriptions if present.
	s.subscriptionInfosMutex.Lock()
	delete(s.subscriptionInfos, s.chainTimeService.SlotToEpoch(data.Slot)-2)
	s.subscriptionInfosMutex.Unlock()

	// Only verify on current slot.
	if s.verifySyncCommitteeInclusion && data.Slot == s.chainTimeService.CurrentSlot() {
		// Verify sync committee participation.
		s.VerifySyncCommitteeMessages(ctx, data)

		// Remove old sync committee data.
		s.syncCommitteeMessenger.RemoveHistoricDataUsedForSlotVerification(data.Slot)
	}
}

// checkEventForReorg check data in the event against information that we already have to see if
// a chain reorg may have occurred, and if so handle it.
func (s *Service) checkEventForReorg(ctx context.Context,
	epoch phase0.Epoch,
	slot phase0.Slot,
	previousDutyDependentRoot phase0.Root,
	currentDutyDependentRoot phase0.Root,
) {
	var zeroRoot phase0.Root

	// Check to see if there is a reorganisation that requires re-fetching duties.
	if s.lastBlockEpoch != 0 {
		if epoch > s.lastBlockEpoch {
			s.log.Trace().
				Uint64("slot", uint64(slot)).
				Str("old_previous_dependent_root", fmt.Sprintf("%#x", s.previousDutyDependentRoot)).
				Str("new_previous_dependent_root", fmt.Sprintf("%#x", previousDutyDependentRoot)).
				Str("old_current_dependent_root", fmt.Sprintf("%#x", s.currentDutyDependentRoot)).
				Str("new_current_dependent_root", fmt.Sprintf("%#x", currentDutyDependentRoot)).
				Msg("Change of epoch")
			// Change of epoch.  Ensure that the new previous dependent root is the same as
			// the old current root.
			if !bytes.Equal(s.previousDutyDependentRoot[:], zeroRoot[:]) &&
				!bytes.Equal(s.currentDutyDependentRoot[:], previousDutyDependentRoot[:]) {
				s.log.Debug().
					Uint64("slot", uint64(slot)).
					Str("old_current_dependent_root", fmt.Sprintf("%#x", s.currentDutyDependentRoot[:])).
					Str("new_previous_dependent_root", fmt.Sprintf("%#x", previousDutyDependentRoot[:])).
					Msg("Previous duty dependent root has changed on epoch transition")
				go s.handlePreviousDependentRootChanged(ctx)
			}
		} else {
			// Existing epoch.  Ensure that the roots are the same.
			if !bytes.Equal(s.previousDutyDependentRoot[:], zeroRoot[:]) &&
				!bytes.Equal(s.previousDutyDependentRoot[:], previousDutyDependentRoot[:]) {
				s.log.Debug().
					Uint64("slot", uint64(slot)).
					Str("old_dependent_root", fmt.Sprintf("%#x", s.previousDutyDependentRoot[:])).
					Str("new_dependent_root", fmt.Sprintf("%#x", previousDutyDependentRoot[:])).
					Msg("Previous duty dependent root has changed")
				go s.handlePreviousDependentRootChanged(ctx)
			}

			if !bytes.Equal(s.currentDutyDependentRoot[:], zeroRoot[:]) &&
				!bytes.Equal(s.currentDutyDependentRoot[:], currentDutyDependentRoot[:]) {
				s.log.Debug().
					Uint64("slot", uint64(slot)).
					Str("old_dependent_root", fmt.Sprintf("%#x", s.currentDutyDependentRoot[:])).
					Str("new_dependent_root", fmt.Sprintf("%#x", currentDutyDependentRoot[:])).
					Msg("Current duty dependent root has changed")
				go s.handleCurrentDependentRootChanged(ctx)
			}
		}
	}

	s.lastBlockEpoch = epoch
	s.previousDutyDependentRoot = previousDutyDependentRoot
	s.currentDutyDependentRoot = currentDutyDependentRoot
}

// fastTrackJobs kicks off jobs when a block has been seen early.
func (s *Service) fastTrackJobs(ctx context.Context,
	slot phase0.Slot,
) {
	if !(s.fastTrackAttestations || s.fastTrackSyncCommittees) {
		// No fast track required.
		return
	}

	// We wait before fast tracking jobs to allow the block some time to propagate around the rest
	// of the network before kicking off attestations and sync committees for the block's slot.
	time.Sleep(s.fastTrackGrace)

	if s.fastTrackAttestations {
		jobName := fmt.Sprintf("Attestations for slot %d", slot)
		if s.scheduler.JobExists(ctx, jobName) {
			s.log.Trace().Msg("Kicking off attestations for slot early due to receiving relevant block")
			s.scheduler.RunJobIfExists(ctx, jobName)
		}
	}

	if s.fastTrackSyncCommittees {
		jobName := fmt.Sprintf("Sync committee messages for slot %d", slot)
		if s.scheduler.JobExists(ctx, jobName) {
			s.log.Trace().Msg("Kicking off sync committee contributions for slot early due to receiving relevant block")
			s.scheduler.RunJobIfExists(ctx, jobName)
		}
	}
}

// handlePreviousDependentRootChanged handles the situation where the previous
// dependent root changed.
func (s *Service) handlePreviousDependentRootChanged(ctx context.Context) {
	// NOT running task in goroutine as there is only one task and this function is always called in a goroutine.

	// We need to refresh the attester duties for this epoch.
	s.refreshAttesterDutiesForEpoch(ctx, s.chainTimeService.CurrentEpoch())
}

// handleCurrentDependentRootChanged handles the situation where the current
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
		attribute.Int64("epoch", util.EpochToInt64(epoch)),
	))
	defer span.End()

	// First thing we do is cancel all scheduled beacon bock proposal jobs for the epoch.
	for slot := s.chainTimeService.FirstSlotOfEpoch(epoch); slot < s.chainTimeService.FirstSlotOfEpoch(epoch+1); slot++ {
		s.scheduler.CancelJobIfExists(ctx, fmt.Sprintf("Early beacon block proposal for slot %d", slot))
		s.scheduler.CancelJobIfExists(ctx, fmt.Sprintf("Beacon block proposal for slot %d", slot))
	}

	_, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, epoch)
	if err != nil {
		s.log.Error().Err(err).Uint64("epoch", uint64(epoch)).Msg("Failed to obtain active validators for epoch")
		return
	}

	// Expect at least one validator.
	if len(validatorIndices) == 0 {
		s.log.Warn().Msg("No active validators; not validating")
		return
	}

	s.scheduleProposals(ctx, epoch, validatorIndices, true /* notCurrentSlot */)
}

func (s *Service) refreshAttesterDutiesForEpoch(ctx context.Context, epoch phase0.Epoch) {
	ctx, span := otel.Tracer("attestantio.vouch.services.controller.standard").Start(ctx, "refreshAttesterDutiesForEpoch", trace.WithAttributes(
		attribute.Int64("epoch", util.EpochToInt64(epoch)),
	))
	defer span.End()

	// If the epoch duties are yet to be scheduled then we don't have anything to do.
	if s.scheduler.JobExists(ctx, fmt.Sprintf("Prepare for epoch %d", epoch)) {
		s.log.Trace().Msg("Refresh not necessary as epoch not yet prepared")
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
		s.log.Error().Err(err).Uint64("epoch", uint64(epoch)).Msg("Failed to obtain active validators for epoch")
		return
	}

	// Expect at least one validator.
	if len(validatorIndices) == 0 {
		s.log.Warn().Msg("No active validators; not validating")
		return
	}

	// Reschedule attestations.
	// Only reschedule current slot if its job was cancelled.
	curentSlotJobCancelled := cancelledJobs[s.chainTimeService.CurrentSlot()]
	go s.scheduleAttestations(ctx, epoch, validatorIndices, !curentSlotJobCancelled)

	// Update beacon committee subscriptions for the next epoch.
	go s.subscribeToBeaconCommittees(ctx, epoch, accounts)
}

// refreshSyncCommitteeDutiesForEpochPeriod refreshes sync committee duties for all epochs in the
// given sync period.
func (s *Service) refreshSyncCommitteeDutiesForEpochPeriod(ctx context.Context, epoch phase0.Epoch) {
	ctx, span := otel.Tracer("attestantio.vouch.services.controller.standard").Start(ctx, "refreshSyncCommitteeDutiesForEpochPeriod", trace.WithAttributes(
		attribute.Int64("epoch", util.EpochToInt64(epoch)),
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
			s.log.Debug().Str("job_name", prepareJobName).Err(err).Msg("Failed to cancel prepare sync committee message job")
		}
		messageJobName := fmt.Sprintf("Sync committee messages for slot %d", slot)
		if err := s.scheduler.CancelJob(ctx, messageJobName); err != nil {
			s.log.Debug().Str("job_name", messageJobName).Err(err).Msg("Failed to cancel sync committee message job")
		}
		aggregateJobName := fmt.Sprintf("Sync committee aggregation for slot %d", slot)
		if err := s.scheduler.CancelJob(ctx, aggregateJobName); err != nil {
			s.log.Debug().Str("job_name", aggregateJobName).Err(err).Msg("Failed to cancel sync committee aggregate job")
		}
	}

	validatorIndices, err := s.syncCommitteeIndicesForEpoch(ctx, firstEpoch)
	if err != nil {
		s.log.Error().Err(err).Uint64("epoch", uint64(firstEpoch)).Msg("Failed to obtain sync committee eligible validators for epoch")
		return
	}

	// Expect at least one validator.
	if len(validatorIndices) == 0 {
		s.log.Warn().Msg("No eligible sync committee validators for epoch; not scheduling sync committee messages")
		return
	}

	// Reschedule sync committee messages.
	go s.scheduleSyncCommitteeMessages(ctx, epoch, validatorIndices, false /* notCurrentSlot */)
}

func (s *Service) subscribeToBeaconCommittees(ctx context.Context,
	epoch phase0.Epoch,
	accounts map[phase0.ValidatorIndex]e2wtypes.Account,
) {
	subscriptionInfo, err := s.beaconCommitteeSubscriber.Subscribe(ctx, epoch, accounts)
	if err != nil {
		s.log.Warn().Err(err).Msg("Failed to subscribe to beacon committees")
		return
	}
	s.subscriptionInfosMutex.Lock()
	s.subscriptionInfos[epoch] = subscriptionInfo
	s.subscriptionInfosMutex.Unlock()
}

// VerifySyncCommitteeMessages handles the "head" events from the beacon node for sync committee verification.
func (s *Service) VerifySyncCommitteeMessages(ctx context.Context, data any) {
	headEvent, ok := data.(*apiv1.HeadEvent)
	if !ok {
		s.log.Error().Msg("Passed invalid data")
		return
	}
	_, span := otel.Tracer("attestantio.vouch.services.controller.standard").Start(ctx, "VerifySyncCommitteeMessages")
	defer span.End()

	// We verify against the previous slot as that is when the sync committee will have reported.
	previousSlot := headEvent.Slot - 1
	currentSlot := headEvent.Slot

	// Logging with the current slot as that is when this code is executed.
	log := s.log.With().
		Uint64("current_slot", uint64(currentSlot)).
		Uint64("previous_slot", uint64(previousSlot)).
		Stringer("block_root", headEvent.Block).
		Logger()
	log.Trace().Msg("Received head event")

	previousSlotData, found := s.syncCommitteeMessenger.GetDataUsedForSlot(previousSlot)
	if !found {
		log.Trace().Msg("No reported sync committee message data for slot; skipping verification")
		return
	}

	var allCommitteeIndices []uint64
	inScopeValidators := make([]uint64, len(previousSlotData.ValidatorToCommitteeIndex))
	keyCount := 0
	for validatorIndex, committeeIndices := range previousSlotData.ValidatorToCommitteeIndex {
		inScopeValidators[keyCount] = uint64(validatorIndex)
		keyCount++
		for _, committeeIndex := range committeeIndices {
			allCommitteeIndices = append(allCommitteeIndices, uint64(committeeIndex))
		}
	}

	log.Trace().Uints64("validators", inScopeValidators).Msg("Verifying sync committee messages for validators")
	monitorSyncCommitteeCurrentCountSet(len(inScopeValidators))

	blockResponse, err := s.signedBeaconBlockProvider.SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{
		Block: headEvent.Block.String(),
	})
	if err != nil {
		log.Debug().Err(err).Msg("Failed to retrieve head block for sync committee verification")
		monitorSyncCommitteeGetHeadBlockFailedInc()
		return
	}
	parentRoot, err := blockResponse.Data.ParentRoot()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get parent root of head block")
		return
	}
	if !bytes.Equal(parentRoot[:], previousSlotData.Root[:]) {
		parentRootString := parentRoot.String()
		previousSlotRoot := previousSlotData.Root.String()
		log.Trace().Str("head_parent_root", parentRootString).Str("broadcast_root", previousSlotRoot).
			Msg("Parent root does not equal sync committee root broadcast")
		monitorSyncCommitteeMessagesHeadMismatchInc(len(inScopeValidators))

		log.Debug().Uints64("incorrect_validator_indices", inScopeValidators).
			Uints64("incorrect_committee_indices", allCommitteeIndices).
			Uints64("missing_validator_indices", []uint64{}).
			Uints64("missing_committee_indices", []uint64{}).
			Uints64("included_validator_indices", []uint64{}).
			Uints64("included_committee_indices", []uint64{}).
			Msg("Verifying sync committee messages for validators complete")
		return
	}
	syncAggregate, err := blockResponse.Data.SyncAggregate()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get sync aggregate retrieved from head block")
		return
	}

	var includedValidatorIndices, includedCommitteeIndices, missingValidatorIndices, missingCommitteeIndices []uint64
	for validatorIndex, committeeIndices := range previousSlotData.ValidatorToCommitteeIndex {
		for _, committeeIndex := range committeeIndices {
			if !syncAggregate.SyncCommitteeBits.BitAt(uint64(committeeIndex)) {
				monitorSyncCommitteeSyncAggregateMissingInc()
				missingValidatorIndices = append(missingValidatorIndices, uint64(validatorIndex))
				missingCommitteeIndices = append(missingCommitteeIndices, uint64(committeeIndex))
				continue
			}
			monitorSyncCommitteeSyncAggregateFoundInc()
			includedValidatorIndices = append(includedValidatorIndices, uint64(validatorIndex))
			includedCommitteeIndices = append(includedCommitteeIndices, uint64(committeeIndex))
		}
	}
	log.Debug().Uints64("incorrect_validator_indices", []uint64{}).
		Uints64("incorrect_committee_indices", []uint64{}).
		Uints64("missing_validator_indices", missingValidatorIndices).
		Uints64("missing_committee_indices", missingCommitteeIndices).
		Uints64("included_validator_indices", includedValidatorIndices).
		Uints64("included_committee_indices", includedCommitteeIndices).
		Msg("Verifying sync committee messages for validators complete")
}
