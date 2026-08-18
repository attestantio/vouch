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
	"sort"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/payloadattester"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// schedulePayloadAttestations schedules payload attestation duties.
func (s *Service) schedulePayloadAttestations(ctx context.Context,
	epoch phase0.Epoch,
	validatorIndices []phase0.ValidatorIndex,
	notCurrentSlot bool,
) {
	if !s.canSchedulePayloadAttestations(validatorIndices) {
		return
	}
	if epoch > s.chainTimeService.CurrentEpoch() && s.payloadAttestationsAlreadyScheduled(ctx, epoch) {
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
	sort.Slice(slots, func(i, j int) bool { return slots[i] < slots[j] })
	for _, slot := range slots {
		s.schedulePayloadAttestation(ctx, dutiesBySlot[slot], accounts)
	}
}

func (s *Service) canSchedulePayloadAttestations(validatorIndices []phase0.ValidatorIndex) bool {
	return len(validatorIndices) > 0 && s.ptcDutiesProvider != nil && s.payloadAttester != nil && s.chainTimeService.CurrentEpoch() >= s.gloasForkEpoch
}

func (s *Service) payloadAttestationsAlreadyScheduled(ctx context.Context, epoch phase0.Epoch) bool {
	for slot := s.chainTimeService.FirstSlotOfEpoch(epoch); slot < s.chainTimeService.FirstSlotOfEpoch(epoch+1); slot++ {
		if s.scheduler.JobExists(ctx, fmt.Sprintf("Payload attestations for slot %d", slot)) {
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

	jobTime := s.chainTimeService.StartOfSlot(duty.Slot()).Add(s.payloadDueDelay)
	deadline := s.chainTimeService.StartOfSlot(duty.Slot()).Add(s.payloadAttestationDelay)
	if err := s.scheduler.ScheduleJob(ctx,
		"Payload attestation",
		fmt.Sprintf("Payload attestations for slot %d", duty.Slot()),
		jobTime,
		func(ctx context.Context) {
			ctx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			s.attestPayload(ctx, duty)
		},
	); err != nil {
		s.log.Error().Err(err).Msg("Failed to schedule payload attestation")
	}
}

func (s *Service) attestPayload(ctx context.Context, duty *payloadattester.Duty) {
	if _, err := s.payloadAttester.Attest(ctx, duty); err != nil {
		s.log.Error().Err(err).Uint64("slot", uint64(duty.Slot())).Msg("Failed to attest to payload timeliness")
	}
}

func (s *Service) refreshPayloadAttestationDutiesForEpoch(ctx context.Context, epoch phase0.Epoch) {
	for slot := s.chainTimeService.FirstSlotOfEpoch(epoch); slot < s.chainTimeService.FirstSlotOfEpoch(epoch+1); slot++ {
		s.scheduler.CancelJobIfExists(ctx, fmt.Sprintf("Payload attestations for slot %d", slot))
	}

	_, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, epoch)
	if err != nil {
		s.log.Error().Err(err).Uint64("epoch", uint64(epoch)).Msg("Failed to obtain payload attestation validators")
		return
	}
	if len(validatorIndices) == 0 {
		return
	}

	s.schedulePayloadAttestations(ctx, epoch, validatorIndices, false)
}
