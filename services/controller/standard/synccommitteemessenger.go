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

// scheduleSyncCommitteeMessages schedules sync committee messages for the given epoch and validator indices.
func (s *Service) scheduleSyncCommitteeMessages(ctx context.Context,
	epoch phase0.Epoch,
	validatorIndices []phase0.ValidatorIndex,
) {
	if len(validatorIndices) == 0 {
		// Nothing to do.
		return
	}

	started := time.Now()
	log.Trace().Uint64("epoch", uint64(epoch)).Msg("Scheduling sync committee messages")

	resp, err := s.syncCommitteeDutiesProvider.SyncCommitteeDuties(ctx, epoch, validatorIndices)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch sync committee message duties")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Int("duties", len(resp)).Msg("Fetched sync committee message duties")

	// We combine the duties for the epoch.
	messageIndices := make(map[phase0.ValidatorIndex][]phase0.CommitteeIndex, len(resp))
	for _, duty := range resp {
		messageIndices[duty.ValidatorIndex] = duty.ValidatorSyncCommitteeIndices
	}
	// log.Trace().Dur("elapsed", time.Since(started)).Str("duties", duty.String()).Msg("Generated sync committee message indices")

	// Obtain the accounts for the validator indices.
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, epoch, validatorIndices)
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain validating accounts for epoch")
		return
	}

	// Now we have the messages we can subscribe to the relevant subnets.

	syncCommitteePeriodFirstSlot := s.chainTimeService.FirstSlotOfEpoch(phase0.Epoch((uint64(epoch) / s.epochsPerSyncCommitteePeriod) * s.epochsPerSyncCommitteePeriod))
	syncCommitteePeriodLastSlot := syncCommitteePeriodFirstSlot + phase0.Slot(s.slotsPerEpoch*s.epochsPerSyncCommitteePeriod) - 1
	if syncCommitteePeriodFirstSlot < s.chainTimeService.CurrentSlot() {
		syncCommitteePeriodFirstSlot = s.chainTimeService.CurrentSlot()
	}
	log.Trace().
		Uint64("first_slot", uint64(syncCommitteePeriodFirstSlot)).
		Uint64("last_slot", uint64(syncCommitteePeriodLastSlot)).
		Msg("Setting sync committee duties for period")

	for slot := syncCommitteePeriodFirstSlot; slot <= syncCommitteePeriodLastSlot; slot++ {
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

			prepareJobTime := s.chainTimeService.StartOfSlot(duty.Slot()).Add(-1 * time.Minute)
			if err := s.scheduler.ScheduleJob(ctx,
				fmt.Sprintf("Prepare sync committee messages for slot %d", duty.Slot()),
				prepareJobTime,
				s.prepareMessageSyncCommittee,
				duty,
			); err != nil {
				log.Error().Err(err).Msg("Failed to schedule prepare sync committee messages")
				return
			}
			jobTime := s.chainTimeService.StartOfSlot(duty.Slot()).Add(s.maxSyncCommitteeMessageDelay)
			if err := s.scheduler.ScheduleJob(ctx,
				fmt.Sprintf("Sync committee messages for slot %d", duty.Slot()),
				jobTime,
				s.messageSyncCommittee,
				duty,
			); err != nil {
				// Don't return here; we want to try to set up as many sync committee message jobs as possible.
				log.Error().Err(err).Msg("Failed to schedule sync committee messages")
			}
		}(synccommitteemessenger.NewDuty(slot, messageIndices), accounts)
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Scheduled sync committee messages")

	// TODO Obi-wan?
	if err := s.syncCommitteesSubscriber.Subscribe(ctx, s.chainTimeService.SlotToEpoch(syncCommitteePeriodLastSlot), resp); err != nil {
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
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Messaged")
}
