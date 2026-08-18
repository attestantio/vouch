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

// gloasDevnet8Spec is the Glamsterdam devnet-8 configuration, as served by
// https://beacon.glamsterdam-devnet-8.ethpandaops.io/eth/v1/config/spec.  It matches the
// consensus-specs v1.7.0-alpha.13 mainnet configuration for every value used here.
func gloasDevnet8Spec() map[string]any {
	return map[string]any{
		"SLOT_DURATION_MS":            uint64(12000),
		"ATTESTATION_DUE_BPS":         uint64(3333),
		"ATTESTATION_DUE_BPS_GLOAS":   uint64(2500),
		"AGGREGATE_DUE_BPS":           uint64(6667),
		"AGGREGATE_DUE_BPS_GLOAS":     uint64(5000),
		"SYNC_MESSAGE_DUE_BPS":        uint64(3333),
		"SYNC_MESSAGE_DUE_BPS_GLOAS":  uint64(2500),
		"CONTRIBUTION_DUE_BPS":        uint64(6667),
		"CONTRIBUTION_DUE_BPS_GLOAS":  uint64(5000),
		"PAYLOAD_DUE_BPS":             uint64(5000),
		"PAYLOAD_ATTESTATION_DUE_BPS": uint64(7500),
	}
}

// TestGloasSpecConformance pins the derived deadlines to the values the Gloas specification
// mandates, rather than to the formula the derivation itself uses.  The slot anatomy at mainnet
// parameters is propose at 0s, attest at 3s, reveal the payload at 6s, and vote on it at 9s.
func TestGloasSpecConformance(t *testing.T) {
	timings := obtainAttestationTimings(gloasDevnet8Spec(), 12*time.Second, true)

	require.Equal(t, 3*time.Second, timings.maxAttestationDelay)
	require.Equal(t, 6*time.Second, timings.attestationAggregationDelay)
	require.Equal(t, 3*time.Second, timings.maxSyncCommitteeMessageDelay)
	require.Equal(t, 6*time.Second, timings.syncCommitteeAggregationDelay)
}

// TestObtainAttestationTimingsIgnoresPreGloasKeys confirms that the unsuffixed keys do not reach the
// Gloas deadlines.  Devnet-7 served ATTESTATION_DUE_BPS_GLOAS but none of the other three suffixed
// keys, so reading the unsuffixed key as a fallback scheduled aggregation at the pre-Gloas 8.0004s
// rather than at the 6s that Gloas requires.
func TestObtainAttestationTimingsIgnoresPreGloasKeys(t *testing.T) {
	devnet7 := map[string]any{
		"SLOT_DURATION_MS":          uint64(12000),
		"ATTESTATION_DUE_BPS":       uint64(3333),
		"ATTESTATION_DUE_BPS_GLOAS": uint64(2500),
		"AGGREGATE_DUE_BPS":         uint64(6667),
		"SYNC_MESSAGE_DUE_BPS":      uint64(3333),
		"CONTRIBUTION_DUE_BPS":      uint64(6667),
	}

	timings := obtainAttestationTimings(devnet7, 12*time.Second, true)

	require.Equal(t, 3*time.Second, timings.maxAttestationDelay)
	require.Equal(t, 6*time.Second, timings.attestationAggregationDelay)
	require.Equal(t, 3*time.Second, timings.maxSyncCommitteeMessageDelay)
	require.Equal(t, 6*time.Second, timings.syncCommitteeAggregationDelay)
}

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
			name:                 "served values",
			spec:                 map[string]any{"SLOT_DURATION_MS": uint64(12000), "ATTESTATION_DUE_BPS_GLOAS": uint64(2500), "AGGREGATE_DUE_BPS_GLOAS": uint64(5000), "SYNC_MESSAGE_DUE_BPS_GLOAS": uint64(1250), "CONTRIBUTION_DUE_BPS_GLOAS": uint64(8750)},
			expectedAttestation:  3 * time.Second,
			expectedAggregation:  6 * time.Second,
			expectedSyncMessage:  1500 * time.Millisecond,
			expectedContribution: 10500 * time.Millisecond,
			gloasActive:          true,
		},
		{
			// A served value that is not a whole number of milliseconds of the slot is used as-is,
			// rather than being rounded to the nearest ratio.
			name:                 "served values need not be round",
			spec:                 map[string]any{"ATTESTATION_DUE_BPS_GLOAS": uint64(3333)},
			expectedAttestation:  3999600 * time.Microsecond,
			expectedAggregation:  6 * time.Second,
			expectedSyncMessage:  3 * time.Second,
			expectedContribution: 6 * time.Second,
			gloasActive:          true,
		},
		{
			name:                 "aggregation fallback",
			spec:                 map[string]any{"ATTESTATION_DUE_BPS_GLOAS": uint64(1250)},
			expectedAttestation:  1500 * time.Millisecond,
			expectedAggregation:  6 * time.Second,
			expectedSyncMessage:  3 * time.Second,
			expectedContribution: 6 * time.Second,
			gloasActive:          true,
		},
		{
			// The fallbacks are the Gloas deadlines, not the pre-Gloas ones, so a node that serves
			// none of the values still schedules to this fork's timings.
			name:                 "all fallbacks",
			spec:                 map[string]any{},
			expectedAttestation:  3 * time.Second,
			expectedAggregation:  6 * time.Second,
			expectedSyncMessage:  3 * time.Second,
			expectedContribution: 6 * time.Second,
			gloasActive:          true,
		},
		{
			// A zero or above-range basis-point value would otherwise schedule the duty at the
			// start of the slot, or after the slot has ended.
			name:                 "out of range values ignored",
			spec:                 map[string]any{"ATTESTATION_DUE_BPS_GLOAS": uint64(0), "AGGREGATE_DUE_BPS_GLOAS": uint64(10001)},
			expectedAttestation:  3 * time.Second,
			expectedAggregation:  6 * time.Second,
			expectedSyncMessage:  3 * time.Second,
			expectedContribution: 6 * time.Second,
			gloasActive:          true,
		},
		{
			// Fallback deadlines must be fractions of the Gloas slot duration, not of
			// SECONDS_PER_SLOT, or they land after the end of a shortened slot.
			name:                 "gloas slot duration drives fallbacks",
			spec:                 map[string]any{"SLOT_DURATION_MS": uint64(6000)},
			expectedAttestation:  1500 * time.Millisecond,
			expectedAggregation:  3 * time.Second,
			expectedSyncMessage:  1500 * time.Millisecond,
			expectedContribution: 3 * time.Second,
			gloasActive:          true,
		},
		{
			name:                 "pre-Gloas ignores served values",
			spec:                 gloasDevnet8Spec(),
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
	spec := map[string]any{"SLOT_DURATION_MS": uint64(6000), "ATTESTATION_DUE_BPS_GLOAS": uint64(2500)}

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
		// Deadlines the operator did not set still follow their own side's derivation: two thirds
		// of the 12-second SECONDS_PER_SLOT before the fork, and half of the 6-second
		// SLOT_DURATION_MS after it.
		require.Equal(t, 8*time.Second, p.preGloasTimings.attestationAggregationDelay)
		require.Equal(t, 3*time.Second, p.gloasTimings.attestationAggregationDelay)
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

// TestObtainPayloadTimings confirms the payload and payload attestation deadlines.  Both duties
// exist only after Gloas, so both follow the Gloas slot duration on either side of the fork.
func TestObtainPayloadTimings(t *testing.T) {
	// The pre-Gloas slot duration, as served in SECONDS_PER_SLOT.
	slotDuration := 12 * time.Second

	tests := []struct {
		name                string
		spec                map[string]any
		expectedPayloadDue  time.Duration
		expectedAttestation time.Duration
	}{
		{
			// The specification values, as devnet-8 serves them: the payload is revealed halfway
			// through the slot and the payload timeliness committee votes at three quarters.
			name:                "served values",
			spec:                gloasDevnet8Spec(),
			expectedPayloadDue:  6 * time.Second,
			expectedAttestation: 9 * time.Second,
		},
		{
			// The payload deadlines are new in Gloas, so the specification defines no
			// _GLOAS-suffixed form of either key and a served suffixed key is not read.
			name:                "unsuffixed keys hold the payload deadlines",
			spec:                map[string]any{"PAYLOAD_DUE_BPS": uint64(2500), "PAYLOAD_DUE_BPS_GLOAS": uint64(7500)},
			expectedPayloadDue:  3 * time.Second,
			expectedAttestation: 9 * time.Second,
		},
		{
			name:                "all fallbacks",
			spec:                map[string]any{},
			expectedPayloadDue:  6 * time.Second,
			expectedAttestation: 9 * time.Second,
		},
		{
			// The payload duties exist only after Gloas, so their fallbacks follow the Gloas slot
			// duration even though the served basis points are absent.
			name:                "gloas slot duration drives fallbacks",
			spec:                map[string]any{"SLOT_DURATION_MS": uint64(6000)},
			expectedPayloadDue:  3 * time.Second,
			expectedAttestation: 4500 * time.Millisecond,
		},
		{
			name:                "out of range values ignored",
			spec:                map[string]any{"PAYLOAD_DUE_BPS": uint64(0), "PAYLOAD_ATTESTATION_DUE_BPS": uint64(10001)},
			expectedPayloadDue:  6 * time.Second,
			expectedAttestation: 9 * time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payloadDue, payloadAttestationDue := obtainPayloadTimings(test.spec, slotDuration)
			require.Equal(t, test.expectedPayloadDue, payloadDue)
			require.Equal(t, test.expectedAttestation, payloadAttestationDue)
		})
	}
}
