// Copyright © 2020 - 2026 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");

package standard

import (
	"testing"
	"time"

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
			name:                 "served values",
			spec:                 map[string]any{"SLOT_DURATION_MS": uint64(12000), "ATTESTATION_DUE_BPS_GLOAS": uint64(2500), "AGGREGATE_DUE_BPS_GLOAS": uint64(5000), "SYNC_MESSAGE_DUE_BPS_GLOAS": uint64(1250), "CONTRIBUTION_DUE_BPS_GLOAS": uint64(8750)},
			expectedAttestation:  3 * time.Second,
			expectedAggregation:  6 * time.Second,
			expectedSyncMessage:  1500 * time.Millisecond,
			expectedContribution: 10500 * time.Millisecond,
			gloasActive:          true,
		},
		{
			name:                 "attestation fallback",
			spec:                 map[string]any{"AGGREGATE_DUE_BPS_GLOAS": uint64(7500)},
			expectedAttestation:  4 * time.Second,
			expectedAggregation:  9 * time.Second,
			expectedSyncMessage:  4 * time.Second,
			expectedContribution: 8 * time.Second,
			gloasActive:          true,
		},
		{
			name:                 "aggregation fallback",
			spec:                 map[string]any{"ATTESTATION_DUE_BPS_GLOAS": uint64(2500)},
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
			name:                 "pre-Gloas ignores served values",
			spec:                 map[string]any{"SLOT_DURATION_MS_GLOAS": uint64(6000), "ATTESTATION_DUE_BPS_GLOAS": uint64(5000), "AGGREGATE_DUE_BPS_GLOAS": uint64(5000)},
			expectedAttestation:  4 * time.Second,
			expectedAggregation:  8 * time.Second,
			expectedSyncMessage:  4 * time.Second,
			expectedContribution: 8 * time.Second,
			gloasActive:          false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attestation, aggregation, syncMessage, contribution := obtainAttestationTimings(test.spec, slotDuration, test.gloasActive)
			require.Equal(t, test.expectedAttestation, attestation)
			require.Equal(t, test.expectedAggregation, aggregation)
			require.Equal(t, test.expectedSyncMessage, syncMessage)
			require.Equal(t, test.expectedContribution, contribution)
		})
	}
}
