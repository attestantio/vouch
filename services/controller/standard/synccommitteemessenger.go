// Copyright © 2021 Attestant Limited.
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
	"github.com/attestantio/vouch/services/synccommitteeaggregator"
	"github.com/attestantio/vouch/services/synccommitteemessenger"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// scheduleSyncCommitteeMessages schedules sync committee messages for the given period and validator indices.
func (s *Service) scheduleSyncCommitteeMessages(ctx context.Context,
	epoch phase0.Epoch,
	validatorIndices []phase0.ValidatorIndex,
	notCurrentSlot bool,
) {
	if len(validatorIndices) == 0 {
		// Nothing to do.
		return
	}
	if s.chainTimeService.CurrentEpoch() < s.altairForkEpoch {
		// Not yet at the Altair epoch; don't schedule anything.
		return
	}

	period := uint64(epoch) / s.epochsPerSyncCommitteePeriod
	firstEpoch := s.firstEpochOfSyncPeriod(period)
	if firstEpoch < s.chainTimeService.CurrentEpoch() {
		firstEpoch = s.chainTimeService.CurrentEpoch()
	}
	// If we are in the sync committee that starts at slot x we need to generate a message during slot x-1
	// for it to be included in slot x, hence -1.
	firstSlot := s.chainTimeService.FirstSlotOfEpoch(firstEpoch) - 1
	if firstSlot < s.chainTimeService.CurrentSlot() {
		firstSlot = s.chainTimeService.CurrentSlot()
	}
	lastEpoch := s.firstEpochOfSyncPeriod(period+1) - 1
	// If we are in the sync committee that ends at slot x we do not generate a message during slot x-1
	// as it will never be included, hence -1.
	lastSlot := s.chainTimeService.FirstSlotOfEpoch(lastEpoch+1) - 2

	started := time.Now()
	log.Trace().Uint64("period", period).Uint64("first_epoch", uint64(firstEpoch)).Uint64("last_epoch", uint64(lastEpoch)).Msg("Scheduling sync committee messages")

	duties, err := s.syncCommitteeDutiesProvider.SyncCommitteeDuties(ctx, firstEpoch, validatorIndices)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch sync committee message duties")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Int("duties", len(duties)).Msg("Fetched sync committee message duties")
	if len(duties) == 0 {
		// No duties; nothing to do.
		return
	}

	// We combine the duties for the epoch.
	messageIndices := make(map[phase0.ValidatorIndex][]phase0.CommitteeIndex, len(duties))
	for _, duty := range duties {
		messageIndices[duty.ValidatorIndex] = duty.ValidatorSyncCommitteeIndices
	}

	// Obtain the accounts for the validator indices.
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, firstEpoch, validatorIndices)
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain validating accounts for epoch")
		return
	}

	// Now we have the messages we can subscribe to the relevant subnets.
	log.Trace().
		Uint64("first_slot", uint64(firstSlot)).
		Uint64("last_slot", uint64(lastSlot)).
		Msg("Setting sync committee duties for period")

	for slot := firstSlot; slot <= lastSlot; slot++ {
		if slot == s.chainTimeService.CurrentSlot() && notCurrentSlot {
			continue
		}
		go func(duty *synccommitteemessenger.Duty, accounts map[phase0.ValidatorIndex]e2wtypes.Account) {
			for _, validatorIndex := range duty.ValidatorIndices() {
				account, exists := accounts[validatorIndex]
				if !exists {
					log.Error().Uint64("validator_index", uint64(validatorIndex)).Msg("No validating account; cannot continue")
					// Continue regardless of error, to attempt to schedule as many valid jobs as possible.
				} else {
					duty.SetAccount(validatorIndex, account)
				}
			}

			// Schedule for 1.5 slots ahead of time.
			prepareJobTime := s.chainTimeService.StartOfSlot(duty.Slot()).Add(-s.slotDuration * 6 / 4)
			if err := s.scheduler.ScheduleJob(ctx,
				fmt.Sprintf("Prepare sync committee messages for slot %d", duty.Slot()),
				prepareJobTime,
				s.prepareMessageSyncCommittee,
				duty,
			); err != nil {
				log.Error().Err(err).Msg("Failed to schedule prepare sync committee messages")
				return
			}
		}(synccommitteemessenger.NewDuty(slot, messageIndices), accounts)
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Scheduled sync committee messages")

	if err := s.syncCommitteesSubscriber.Subscribe(ctx, lastEpoch+1, duties); err != nil {
		log.Error().Err(err).Msg("Failed to submit sync committee subscribers")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted sync committee subscribers")
}

func (s *Service) prepareMessageSyncCommittee(ctx context.Context, data interface{}) {
	started := time.Now()
	duty, ok := data.(*synccommitteemessenger.Duty)
	if !ok {
		log.Error().Msg("Passed invalid data")
		return
	}
	log := log.With().Uint64("slot", uint64(s.chainTimeService.CurrentSlot())).Logger()

	if err := s.syncCommitteeMessenger.Prepare(ctx, duty); err != nil {
		log.Error().Uint64("sync_committee_slot", uint64(duty.Slot())).Err(err).Msg("Failed to prepare sync committee message")
		return
	}

	// At this point we can schedule the message job.
	jobTime := s.chainTimeService.StartOfSlot(duty.Slot()).Add(s.maxSyncCommitteeMessageDelay)
	if err := s.scheduler.ScheduleJob(ctx,
		fmt.Sprintf("Sync committee messages for slot %d", duty.Slot()),
		jobTime,
		s.messageSyncCommittee,
		duty,
	); err != nil {
		log.Error().Err(err).Msg("Failed to schedule sync committee messages")
		return
	}

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Prepared")
}

func (s *Service) messageSyncCommittee(ctx context.Context, data interface{}) {
	started := time.Now()
	duty, ok := data.(*synccommitteemessenger.Duty)
	if !ok {
		log.Error().Msg("Passed invalid data")
		return
	}
	log := log.With().Uint64("slot", uint64(s.chainTimeService.CurrentSlot())).Logger()

	_, err := s.syncCommitteeMessenger.Message(ctx, duty)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to submit sync committee message")
		return
	}

	// At this point we can schedule an aggregation job if reqiured.
	aggregateValidatorIndices := make([]phase0.ValidatorIndex, 0)
	selectionProofs := make(map[phase0.ValidatorIndex]map[uint64]phase0.BLSSignature)
	for _, validatorIndex := range duty.ValidatorIndices() {
		aggregationIndices := duty.AggregatorSubcommittees(validatorIndex)
		if len(aggregationIndices) > 0 {
			aggregateValidatorIndices = append(aggregateValidatorIndices, validatorIndex)
			selectionProofs[validatorIndex] = aggregationIndices
		}
	}
	if len(aggregateValidatorIndices) > 0 {
		aggregatorDuty := &synccommitteeaggregator.Duty{
			Slot:             duty.Slot(),
			ValidatorIndices: aggregateValidatorIndices,
			SelectionProofs:  selectionProofs,
			Accounts:         duty.Accounts(),
		}
		if err := s.scheduler.ScheduleJob(ctx,
			fmt.Sprintf("Sync committee aggregation for slot %d", duty.Slot()),
			s.chainTimeService.StartOfSlot(duty.Slot()).Add(s.slotDuration*2/3),
			s.syncCommitteeAggregator.Aggregate,
			aggregatorDuty,
		); err != nil {
			log.Error().Err(err).Msg("Failed to schedule sync committee attestation aggregation job")
		}
	}

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Messaged")
}

// firstEpochOfSyncPeriod calculates the first epoch of the given sync period.
func (s *Service) firstEpochOfSyncPeriod(period uint64) phase0.Epoch {
	epoch := phase0.Epoch(period * s.epochsPerSyncCommitteePeriod)
	if epoch < s.altairForkEpoch {
		epoch = s.altairForkEpoch
	}
	return epoch
}
