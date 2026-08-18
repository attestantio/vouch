// Copyright © 2026 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License").

package standard

import (
	"context"
	"fmt"
	"sort"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/payloadattester"
)

// schedulePayloadAttestations schedules payload attestation duties.
func (s *Service) schedulePayloadAttestations(ctx context.Context,
	epoch phase0.Epoch,
	validatorIndices []phase0.ValidatorIndex,
	notCurrentSlot bool,
) {
	if len(validatorIndices) == 0 || s.ptcDutiesProvider == nil || s.payloadAttester == nil {
		return
	}
	if s.chainTimeService.CurrentEpoch() < s.gloasForkEpoch {
		return
	}
	if epoch > s.chainTimeService.CurrentEpoch() {
		for slot := s.chainTimeService.FirstSlotOfEpoch(epoch); slot < s.chainTimeService.FirstSlotOfEpoch(epoch+1); slot++ {
			if s.scheduler.JobExists(ctx, fmt.Sprintf("Payload attestations for slot %d", slot)) {
				s.log.Trace().Uint64("epoch", uint64(epoch)).Msg("Payload attestation duties already scheduled")
				return
			}
		}
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
	dutiesBySlot := make(map[phase0.Slot]*payloadattester.Duty)
	indices := make([]phase0.ValidatorIndex, 0, len(response.Data))
	seenIndices := make(map[phase0.ValidatorIndex]bool)
	for _, duty := range response.Data {
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
		duty := dutiesBySlot[slot]
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
