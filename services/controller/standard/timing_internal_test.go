// Copyright © 2020 - 2026 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");

package standard

import (
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/stretchr/testify/require"
)

func TestObtainAttestationTimings(t *testing.T) {
	slotDuration := 12 * time.Second

	tests := []struct {
		name                 string
		spec                 map[string]any
		expectedAttestation  time.Duration
		expectedAggregation  time.Duration
		expectedSyncMessage  time.Duration
		expectedContribution time.Duration
		gloasActive          bool
	}{
		{
			// The plain key names are what /eth/v1/config/spec serves for values introduced at
			// Gloas, so they are the branch exercised against a real beacon node.
			name:                 "served values",
			spec:                 map[string]any{"SLOT_DURATION_MS": uint64(12000), "ATTESTATION_DUE_BPS": uint64(2500), "AGGREGATE_DUE_BPS": uint64(5000), "SYNC_MESSAGE_DUE_BPS": uint64(1250), "CONTRIBUTION_DUE_BPS": uint64(8750)},
			expectedAttestation:  3 * time.Second,
			expectedAggregation:  6 * time.Second,
			expectedSyncMessage:  1500 * time.Millisecond,
			expectedContribution: 10500 * time.Millisecond,
			gloasActive:          true,
		},
		{
			name:                 "fork-suffixed values take precedence",
			spec:                 map[string]any{"ATTESTATION_DUE_BPS": uint64(2500), "ATTESTATION_DUE_BPS_GLOAS": uint64(5000)},
			expectedAttestation:  6 * time.Second,
			expectedAggregation:  8 * time.Second,
			expectedSyncMessage:  4 * time.Second,
			expectedContribution: 8 * time.Second,
			gloasActive:          true,
		},
		{
			name:                 "attestation fallback",
			spec:                 map[string]any{"AGGREGATE_DUE_BPS": uint64(7500)},
			expectedAttestation:  4 * time.Second,
			expectedAggregation:  9 * time.Second,
			expectedSyncMessage:  4 * time.Second,
			expectedContribution: 8 * time.Second,
			gloasActive:          true,
		},
		{
			name:                 "aggregation fallback",
			spec:                 map[string]any{"ATTESTATION_DUE_BPS": uint64(2500)},
			expectedAttestation:  3 * time.Second,
			expectedAggregation:  8 * time.Second,
			expectedSyncMessage:  4 * time.Second,
			expectedContribution: 8 * time.Second,
			gloasActive:          true,
		},
		{
			name:                 "all fallbacks",
			spec:                 map[string]any{},
			expectedAttestation:  4 * time.Second,
			expectedAggregation:  8 * time.Second,
			expectedSyncMessage:  4 * time.Second,
			expectedContribution: 8 * time.Second,
			gloasActive:          true,
		},
		{
			// A zero or above-range basis-point value would otherwise schedule the duty at the
			// start of the slot, or after the slot has ended.
			name:                 "out of range values ignored",
			spec:                 map[string]any{"ATTESTATION_DUE_BPS": uint64(0), "AGGREGATE_DUE_BPS": uint64(10001)},
			expectedAttestation:  4 * time.Second,
			expectedAggregation:  8 * time.Second,
			expectedSyncMessage:  4 * time.Second,
			expectedContribution: 8 * time.Second,
			gloasActive:          true,
		},
		{
			// Fallback deadlines must be fractions of the Gloas slot duration, not of
			// SECONDS_PER_SLOT, or they land after the end of a shortened slot.
			name:                 "gloas slot duration drives fallbacks",
			spec:                 map[string]any{"SLOT_DURATION_MS": uint64(6000)},
			expectedAttestation:  2 * time.Second,
			expectedAggregation:  4 * time.Second,
			expectedSyncMessage:  2 * time.Second,
			expectedContribution: 4 * time.Second,
			gloasActive:          true,
		},
		{
			name:                 "pre-Gloas ignores served values",
			spec:                 map[string]any{"SLOT_DURATION_MS": uint64(6000), "ATTESTATION_DUE_BPS": uint64(5000), "AGGREGATE_DUE_BPS": uint64(5000)},
			expectedAttestation:  4 * time.Second,
			expectedAggregation:  8 * time.Second,
			expectedSyncMessage:  4 * time.Second,
			expectedContribution: 8 * time.Second,
			gloasActive:          false,
		},
		{
			// The pre-Gloas derivation must reproduce the 4s/8s that main.go previously supplied
			// as hardcoded viper defaults, so that defaulting those options to 0 (and thereby
			// letting the derivation run) leaves a 12-second chain unchanged.
			name:                 "pre-Gloas derivation reproduces the former hardcoded defaults",
			spec:                 map[string]any{},
			expectedAttestation:  4 * time.Second,
			expectedAggregation:  8 * time.Second,
			expectedSyncMessage:  4 * time.Second,
			expectedContribution: 8 * time.Second,
			gloasActive:          false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			timings := obtainAttestationTimings(test.spec, slotDuration, test.gloasActive)
			require.Equal(t, test.expectedAttestation, timings.maxAttestationDelay)
			require.Equal(t, test.expectedAggregation, timings.attestationAggregationDelay)
			require.Equal(t, test.expectedSyncMessage, timings.maxSyncCommitteeMessageDelay)
			require.Equal(t, test.expectedContribution, timings.syncCommitteeAggregationDelay)
		})
	}
}

// TestSetDefaultDelaysOverrides confirms that an explicit operator value replaces the derived
// deadline on both sides of the fork, and that an unset value leaves each side its own derivation.
func TestSetDefaultDelaysOverrides(t *testing.T) {
	spec := map[string]any{"SLOT_DURATION_MS": uint64(6000), "ATTESTATION_DUE_BPS": uint64(2500)}

	t.Run("derived", func(t *testing.T) {
		p := &parameters{}
		p.setDefaultDelays(spec, 12*time.Second)
		require.Equal(t, 4*time.Second, p.preGloasTimings.maxAttestationDelay)
		require.Equal(t, 1500*time.Millisecond, p.gloasTimings.maxAttestationDelay)
	})

	t.Run("override applies to both sides", func(t *testing.T) {
		p := &parameters{maxAttestationDelay: 5 * time.Second}
		p.setDefaultDelays(spec, 12*time.Second)
		require.Equal(t, 5*time.Second, p.preGloasTimings.maxAttestationDelay)
		require.Equal(t, 5*time.Second, p.gloasTimings.maxAttestationDelay)
		// Deadlines the operator did not set still follow their own side's derivation.
		require.Equal(t, 8*time.Second, p.preGloasTimings.attestationAggregationDelay)
		require.Equal(t, 4*time.Second, p.gloasTimings.attestationAggregationDelay)
	})
}

// slotEpochChainTime resolves slots to epochs with a fixed number of slots per epoch.  The duty
// timing selector uses only SlotToEpoch, so the remaining methods are left unimplemented.
type slotEpochChainTime struct {
	chaintime.Service
	slotsPerEpoch uint64
}

func (c *slotEpochChainTime) SlotToEpoch(slot phase0.Slot) phase0.Epoch {
	return phase0.Epoch(uint64(slot) / c.slotsPerEpoch)
}

// TestTimingsForSlot confirms that the deadline set follows the duty's own slot.  Duties are
// scheduled up to an epoch ahead, so a process running before the fork schedules duties on both
// sides of it and must not apply the deadlines of the epoch it happens to be in.
func TestTimingsForSlot(t *testing.T) {
	const slotsPerEpoch = 32
	const gloasForkEpoch = 5

	s := &Service{
		chainTimeService: &slotEpochChainTime{slotsPerEpoch: slotsPerEpoch},
		gloasForkEpoch:   gloasForkEpoch,
		preGloasTimings:  dutyTimings{maxAttestationDelay: 4 * time.Second},
		gloasTimings:     dutyTimings{maxAttestationDelay: 3 * time.Second},
	}

	tests := []struct {
		name     string
		slot     phase0.Slot
		expected time.Duration
	}{
		{name: "well before the fork", slot: 0, expected: 4 * time.Second},
		{name: "last slot before the fork", slot: slotsPerEpoch*gloasForkEpoch - 1, expected: 4 * time.Second},
		{name: "first slot of the fork", slot: slotsPerEpoch * gloasForkEpoch, expected: 3 * time.Second},
		{name: "well after the fork", slot: slotsPerEpoch * (gloasForkEpoch + 10), expected: 3 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, s.timingsForSlot(test.slot).maxAttestationDelay)
		})
	}
}

// TestTimingsForSlotWithoutGloas confirms that a chain whose spec does not carry GLOAS_FORK_EPOCH,
// for which HardForkEpoch returns the far future epoch, stays on the pre-Gloas deadlines.
func TestTimingsForSlotWithoutGloas(t *testing.T) {
	s := &Service{
		chainTimeService: &slotEpochChainTime{slotsPerEpoch: 32},
		gloasForkEpoch:   0xffffffffffffffff,
		preGloasTimings:  dutyTimings{maxAttestationDelay: 4 * time.Second},
		gloasTimings:     dutyTimings{maxAttestationDelay: 3 * time.Second},
	}

	require.Equal(t, 4*time.Second, s.timingsForSlot(0).maxAttestationDelay)
	require.Equal(t, 4*time.Second, s.timingsForSlot(1<<40).maxAttestationDelay)
}
