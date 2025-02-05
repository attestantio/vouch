// Copyright © 2020 - 2022 Attestant Limited.
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
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
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
	s.log.Trace().Uint64("epoch", uint64(epoch)).Msg("Scheduling attestations")

	attesterDutiesResponse, err := s.attesterDutiesProvider.AttesterDuties(ctx, &api.AttesterDutiesOpts{
		Epoch:   epoch,
		Indices: validatorIndices,
	})
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to fetch attester duties")
		return
	}
	attesterDuties := attesterDutiesResponse.Data
	s.log.Trace().Dur("elapsed", time.Since(started)).Int("duties", len(attesterDuties)).Msg("Fetched attester duties")

	// Generate Vouch duties from the response.
	filteredDuties := make([]*apiv1.AttesterDuty, 0, len(attesterDuties))
	firstSlot := s.chainTimeService.FirstSlotOfEpoch(epoch)
	lastSlot := s.chainTimeService.FirstSlotOfEpoch(epoch+1) - 1
	for _, duty := range attesterDuties {
		if duty.Slot < firstSlot || duty.Slot > lastSlot {
			s.log.Warn().
				Uint64("epoch", uint64(epoch)).
				Uint64("duty_slot", uint64(duty.Slot)).
				Msg("Attester duty has invalid slot for requested epoch; ignoring")
			continue
		}
		filteredDuties = append(filteredDuties, duty)
	}
	s.log.Trace().Dur("elapsed", time.Since(started)).Int("duties", len(filteredDuties)).Msg("Filtered attester duties")

	duties, err := attester.MergeDuties(ctx, filteredDuties)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to merge attester duties")
		return
	}
	s.log.Trace().Dur("elapsed", time.Since(started)).Int("duties", len(duties)).Msg("Merged attester duties")

	if e := s.log.Trace(); e.Enabled() {
		e.Msg("Received attester duties")
		for _, duty := range duties {
			s.log.Trace().
				Uint64("slot", uint64(duty.Slot())).
				Strs("duties", duty.Tuples()).
				Msg("Attester duties for slot")
		}
	}

	currentSlot := s.chainTimeService.CurrentSlot()
	for _, duty := range duties {
		// Do not schedule attestations for past slots (or the current slot if so instructed).
		if duty.Slot() < currentSlot {
			s.log.Debug().
				Uint64("attestation_slot", uint64(duty.Slot())).
				Uint64("current_slot", uint64(currentSlot)).
				Msg("Attestation for a past slot; not scheduling")
			continue
		}
		if duty.Slot() == currentSlot && notCurrentSlot {
			s.log.Debug().
				Uint64("attestation_slot", uint64(duty.Slot())).
				Uint64("current_slot", uint64(currentSlot)).
				Msg("Attestation for the current slot; not scheduling")
			continue
		}

		// Make a note that we are carrying out attestations at the given slot.
		s.pendingAttestationsMutex.Lock()
		s.pendingAttestations[duty.Slot()] = true
		s.pendingAttestationsMutex.Unlock()

		go func(duty *attester.Duty) {
			jobTime := s.chainTimeService.StartOfSlot(duty.Slot()).Add(s.maxAttestationDelay)
			if err := s.scheduler.ScheduleJob(ctx,
				"Attest",
				fmt.Sprintf("Attestations for slot %d", duty.Slot()),
				jobTime,
				func(ctx context.Context) { s.AttestAndScheduleAggregate(ctx, duty) },
			); err != nil {
				// Don't return here; we want to try to set up as many attester jobs as possible.
				s.log.Error().Err(err).Msg("Failed to schedule attestation")
			}
		}(duty)
	}
	s.log.Trace().Dur("elapsed", time.Since(started)).Msg("Scheduled attestations")
}

// AttestAndScheduleAggregate attests, then schedules aggregation jobs as required.
func (s *Service) AttestAndScheduleAggregate(ctx context.Context, duty *attester.Duty) {
	started := time.Now()
	log := s.log.With().Uint64("slot", uint64(duty.Slot())).Logger()

	// At the end of this function note that we have carried out the attestation process
	// for this slot, regardless of result.  This allows the main codebase to shut down
	// only after attestations have completed for the given slot.
	defer func() {
		s.pendingAttestationsMutex.Lock()
		delete(s.pendingAttestations, duty.Slot())
		s.pendingAttestationsMutex.Unlock()
	}()

	attestations, err := s.attester.Attest(ctx, duty)
	if err != nil {
		log.Error().Err(err).Msg("Failed to attest")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Attested")

	if len(attestations) == 0 {
		log.Debug().Msg("No attestations; nothing to aggregate")
		return
	}

	firstAttestationData, err := attestations[0].Data()
	if err != nil || firstAttestationData == nil {
		log.Error().Err(err).Msg("Failed to get first attestation data")
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
		attestationData, err := attestation.Data()
		if err != nil {
			log.Debug().Msg("No attestation data; not aggregating")
			continue
		}
		committeeIndex := attestationData.Index
		if s.handlingElectra && epoch >= s.electraForkEpoch {
			committeeIndex, err = attestation.CommitteeIndex()
			if err != nil {
				log.Debug().Msg("Failed to get committee index from committee bits; not aggregating")
				continue
			}
		}
		log := log.With().Uint64("attestation_slot", uint64(attestationData.Slot)).Uint64("committee_index", uint64(committeeIndex)).Logger()
		slotInfoMap, exists := subscriptionInfoMap[attestationData.Slot]
		if !exists {
			log.Debug().Msg("No slot info; not aggregating")
			continue
		}
		// Do not schedule aggregations for past slots.
		currentSlot := s.chainTimeService.CurrentSlot()
		if attestationData.Slot < currentSlot {
			log.Debug().Uint64("current_slot", uint64(currentSlot)).Msg("Aggregation in the past; not scheduling")
			continue
		}
		info, exists := slotInfoMap[committeeIndex]
		if !exists {
			log.Debug().Uint64("committee_index", uint64(committeeIndex)).Msg("No committee info; not aggregating")
			continue
		}
		log = log.With().Uint64("validator_index", uint64(info.Duty.ValidatorIndex)).Logger()
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
			attestationDataRoot, err := attestationData.HashTreeRoot()
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
				CommitteeIndex:      committeeIndex,
			}
			if err := s.scheduler.ScheduleJob(ctx,
				"Aggregate attestations",
				fmt.Sprintf("Beacon block attestation aggregation for slot %d committee %d", attestationData.Slot, committeeIndex),
				s.chainTimeService.StartOfSlot(attestationData.Slot).Add(s.attestationAggregationDelay),
				func(ctx context.Context) { s.attestationAggregator.Aggregate(ctx, aggregatorDuty) },
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
