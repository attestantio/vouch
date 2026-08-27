// Copyright © 2026 Attestant Limited.
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
	"slices"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/payloadattester"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// payloadAttestationGrace is added to the payload attestation deadline before the vote is cast.  A
// beacon node does not serve payload attestation data it does not yet consider final, and one whose
// clock trails ours has not reached the deadline when we do, so firing exactly on the deadline can
// return nothing at all.  This covers that skew and still leaves the rest of the slot for the vote
// to propagate.
const payloadAttestationGrace = 250 * time.Millisecond

// payloadAttestationJobName provides the scheduler job name for a slot's payload attestations.
func payloadAttestationJobName(slot phase0.Slot) string {
	return fmt.Sprintf("Payload attestations for slot %d", slot)
}

// schedulePayloadAttestations schedules payload attestation duties.
func (s *Service) schedulePayloadAttestations(ctx context.Context,
	epoch phase0.Epoch,
	validatorIndices []phase0.ValidatorIndex,
	notCurrentSlot bool,
) {
	if !s.canSchedulePayloadAttestations(epoch, validatorIndices) {
		return
	}
	// The epoch is scheduled from whichever of the epoch ticker and the following epoch's
	// preparation reaches it first, so check every epoch rather than only future ones: without
	// this the ticker refetches the duties the preparation already scheduled and then fails to
	// schedule every one of their jobs.
	if s.payloadAttestationsAlreadyScheduled(ctx, epoch) {
		s.log.Trace().Uint64("epoch", uint64(epoch)).Msg("Payload attestation duties already scheduled")
		return
	}

	response, err := s.ptcDutiesProvider.PTCDuties(ctx, &api.PTCDutiesOpts{
		Epoch:   epoch,
		Indices: validatorIndices,
	})
	if err != nil {
		s.log.Error().Err(err).Uint64("epoch", uint64(epoch)).Msg("Failed to fetch payload attestation duties")
		return
	}
	if response == nil || len(response.Data) == 0 {
		return
	}

	firstSlot := s.chainTimeService.FirstSlotOfEpoch(epoch)
	lastSlot := s.chainTimeService.FirstSlotOfEpoch(epoch+1) - 1
	currentSlot := s.chainTimeService.CurrentSlot()
	dutiesBySlot, indices := payloadAttestationDuties(response.Data, firstSlot, lastSlot, currentSlot, notCurrentSlot)
	if len(dutiesBySlot) == 0 {
		return
	}

	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, epoch, indices)
	if err != nil {
		s.log.Error().Err(err).Uint64("epoch", uint64(epoch)).Msg("Failed to obtain payload attestation accounts")
		return
	}

	slots := make([]phase0.Slot, 0, len(dutiesBySlot))
	for slot := range dutiesBySlot {
		slots = append(slots, slot)
	}
	slices.Sort(slots)
	for _, slot := range slots {
		s.schedulePayloadAttestation(ctx, dutiesBySlot[slot], accounts)
	}
}

// canSchedulePayloadAttestations reports whether the duties for the given epoch can be scheduled.
// The fork test is on the epoch being scheduled rather than on the current one: the epoch after the
// fork epoch is prepared from the epoch before it, where the current epoch is still pre-Gloas, so
// testing the current epoch would drop the first Gloas epoch's duties.
func (s *Service) canSchedulePayloadAttestations(epoch phase0.Epoch, validatorIndices []phase0.ValidatorIndex) bool {
	return len(validatorIndices) > 0 && s.ptcDutiesProvider != nil && s.payloadAttester != nil && epoch >= s.gloasForkEpoch
}

func (s *Service) payloadAttestationsAlreadyScheduled(ctx context.Context, epoch phase0.Epoch) bool {
	for slot := s.chainTimeService.FirstSlotOfEpoch(epoch); slot < s.chainTimeService.FirstSlotOfEpoch(epoch+1); slot++ {
		if s.scheduler.JobExists(ctx, payloadAttestationJobName(slot)) {
			return true
		}
	}
	return false
}

func payloadAttestationDuties(data []*apiv1.PTCDuty,
	firstSlot phase0.Slot,
	lastSlot phase0.Slot,
	currentSlot phase0.Slot,
	notCurrentSlot bool,
) (map[phase0.Slot]*payloadattester.Duty, []phase0.ValidatorIndex) {
	dutiesBySlot := make(map[phase0.Slot]*payloadattester.Duty)
	indices := make([]phase0.ValidatorIndex, 0, len(data))
	seenIndices := make(map[phase0.ValidatorIndex]bool)
	for _, duty := range data {
		if duty == nil || duty.Slot < firstSlot || duty.Slot > lastSlot || duty.Slot < currentSlot || (duty.Slot == currentSlot && notCurrentSlot) {
			continue
		}
		if existing, exists := dutiesBySlot[duty.Slot]; exists {
			existing.AddDuty(duty)
		} else {
			dutiesBySlot[duty.Slot] = payloadattester.NewDuty(duty)
		}
		if !seenIndices[duty.ValidatorIndex] {
			indices = append(indices, duty.ValidatorIndex)
			seenIndices[duty.ValidatorIndex] = true
		}
	}
	return dutiesBySlot, indices
}

//nolint:godox // The TODO below is tracked as follow-up work, not left as a loose end.
func (s *Service) schedulePayloadAttestation(ctx context.Context,
	duty *payloadattester.Duty,
	accounts map[phase0.ValidatorIndex]e2wtypes.Account,
) {
	for _, index := range duty.ValidatorIndices() {
		account, exists := accounts[index]
		if !exists {
			s.log.Error().Uint64("validator_index", uint64(index)).Msg("No validating account for payload attestation duty")
			continue
		}
		duty.SetAccount(index, account)
	}

	// TODO: take the payload-available event once go-eth2-client exposes the SSE topic.
	// The vote would then be cast as soon as the beacon node reports the payload available, keeping
	// this deadline as the backstop.  Prysm's validator waits on that event or this deadline,
	// whichever comes first, which votes earlier in the common case without ever asking before the
	// answer is final.
	jobTime := s.chainTimeService.StartOfSlot(duty.Slot()).Add(s.payloadAttestationDelay).Add(payloadAttestationGrace)
	// The vote is cast at the attestation deadline, so its context runs to the end of the slot:
	// bounding it at that deadline would cut off the signing and submission the vote depends on.
	deadline := s.chainTimeService.StartOfSlot(duty.Slot() + 1)
	if err := s.scheduler.ScheduleJob(ctx,
		"Payload attestation",
		payloadAttestationJobName(duty.Slot()),
		jobTime,
		func(ctx context.Context) {
			ctx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			s.attestPayload(ctx, duty)
		},
	); err != nil {
		s.log.Error().Err(err).Msg("Failed to schedule payload attestation")
		return
	}
	if err := s.payloadAttester.Prepare(ctx, duty); err != nil {
		s.log.Error().Err(err).Uint64("slot", uint64(duty.Slot())).Msg("Failed to prepare payload attestation")
	}
}

func (s *Service) attestPayload(ctx context.Context, duty *payloadattester.Duty) {
	if _, err := s.payloadAttester.Attest(ctx, duty); err != nil {
		s.log.Error().Err(err).Uint64("slot", uint64(duty.Slot())).Msg("Failed to attest to payload timeliness")
	}
}

func (s *Service) refreshPayloadAttestationDutiesForEpoch(ctx context.Context, epoch phase0.Epoch) {
	// If the epoch duties are yet to be scheduled then we don't have anything to do.
	if s.scheduler.JobExists(ctx, fmt.Sprintf("Prepare for epoch %d", epoch)) {
		s.log.Trace().Msg("Payload attestation refresh not necessary as epoch not yet prepared")
		return
	}

	cancelledJobs := make(map[phase0.Slot]bool)
	for slot := s.chainTimeService.FirstSlotOfEpoch(epoch); slot < s.chainTimeService.FirstSlotOfEpoch(epoch+1); slot++ {
		if err := s.scheduler.CancelJob(ctx, payloadAttestationJobName(slot)); err == nil {
			cancelledJobs[slot] = true
		}
	}

	_, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, epoch)
	if err != nil {
		s.log.Error().Err(err).Uint64("epoch", uint64(epoch)).Msg("Failed to obtain payload attestation validators")
		return
	}
	if len(validatorIndices) == 0 {
		return
	}

	// Only reschedule the current slot if its job was cancelled.  If it was not then it has
	// already run, and rescheduling it would place a job in the past that the scheduler runs
	// immediately, attesting to the same slot's payload twice.
	currentSlotJobCancelled := cancelledJobs[s.chainTimeService.CurrentSlot()]
	s.schedulePayloadAttestations(ctx, epoch, validatorIndices, !currentSlotJobCancelled)
}
