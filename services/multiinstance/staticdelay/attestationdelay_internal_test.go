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

package staticdelay

import (
	"context"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// fixedSpecProvider serves a fixed spec, so each test controls exactly which keys the node serves.
type fixedSpecProvider map[string]any

func (s fixedSpecProvider) Spec(_ context.Context, _ *api.SpecOpts) (*api.Response[map[string]any], error) {
	return &api.Response[map[string]any]{Data: s}, nil
}

func newStaticDelayService(t *testing.T, spec fixedSpecProvider) *Service {
	t.Helper()
	ctx := context.Background()

	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(spec),
	)
	require.NoError(t, err)

	s, err := New(ctx,
		WithLogLevel(zerolog.Disabled),
		WithSpecProvider(spec),
		WithAttestationPoolProvider(mock.NewAttestationPoolProvider()),
		WithBeaconBlockHeadersProvider(mock.NewBeaconBlockHeadersProvider()),
		WithChainTime(chainTime),
		WithAttesterDelay(time.Second),
	)
	require.NoError(t, err)

	return s
}

// TestAttestationDelay confirms that the base delay is chosen from the duty's slot, so a process
// running across the fork switches to the Gloas deadline at the first Gloas slot.
func TestAttestationDelay(t *testing.T) {
	const gloasForkEpoch = 5
	const slotsPerEpoch = 32
	spec := fixedSpecProvider{
		"SECONDS_PER_SLOT":          12 * time.Second,
		"SLOTS_PER_EPOCH":           uint64(slotsPerEpoch),
		"INTERVALS_PER_SLOT":        uint64(3),
		"SLOT_DURATION_MS":          uint64(12000),
		"ATTESTATION_DUE_BPS_GLOAS": uint64(2500),
		"GLOAS_FORK_EPOCH":          uint64(gloasForkEpoch),
	}
	s := newStaticDelayService(t, spec)

	tests := []struct {
		name     string
		slot     phase0.Slot
		expected time.Duration
	}{
		{
			name:     "PreGloas",
			slot:     1,
			expected: 4 * time.Second,
		},
		{
			name:     "LastSlotBeforeGloas",
			slot:     slotsPerEpoch*gloasForkEpoch - 1,
			expected: 4 * time.Second,
		},
		{
			name:     "FirstGloasSlot",
			slot:     slotsPerEpoch * gloasForkEpoch,
			expected: 3 * time.Second,
		},
		{
			name:     "WellAfterGloas",
			slot:     slotsPerEpoch * (gloasForkEpoch + 10),
			expected: 3 * time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, s.attestationDelay(test.slot))
		})
	}
}

// TestGloasAttestationDelay confirms the Gloas deadline follows the spec, and falls back to the
// Gloas deadline itself when the node does not serve a usable value.
func TestGloasAttestationDelay(t *testing.T) {
	tests := []struct {
		name     string
		spec     fixedSpecProvider
		expected time.Duration
	}{
		{
			name: "GloasKeysMissing",
			spec: fixedSpecProvider{
				"SECONDS_PER_SLOT": 12 * time.Second,
				"SLOTS_PER_EPOCH":  uint64(32),
				"GLOAS_FORK_EPOCH": uint64(0),
			},
			expected: 3 * time.Second,
		},
		{
			name: "SlotDurationDiffers",
			spec: fixedSpecProvider{
				"SECONDS_PER_SLOT":          12 * time.Second,
				"SLOTS_PER_EPOCH":           uint64(32),
				"SLOT_DURATION_MS":          uint64(6000),
				"ATTESTATION_DUE_BPS_GLOAS": uint64(2500),
				"GLOAS_FORK_EPOCH":          uint64(0),
			},
			expected: 1500 * time.Millisecond,
		},
		{
			name: "DueBPSOutOfRange",
			spec: fixedSpecProvider{
				"SECONDS_PER_SLOT":          12 * time.Second,
				"SLOTS_PER_EPOCH":           uint64(32),
				"SLOT_DURATION_MS":          uint64(12000),
				"ATTESTATION_DUE_BPS_GLOAS": uint64(10001),
				"GLOAS_FORK_EPOCH":          uint64(0),
			},
			expected: 3 * time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newStaticDelayService(t, test.spec)
			require.Equal(t, test.expected, s.attestationDelay(1))
		})
	}
}

// TestAttestationDelayWithoutGloas confirms that a chain with no Gloas fork scheduled keeps the
// pre-Gloas deadline on every slot.
func TestAttestationDelayWithoutGloas(t *testing.T) {
	s := newStaticDelayService(t, fixedSpecProvider{
		"SECONDS_PER_SLOT":          12 * time.Second,
		"SLOTS_PER_EPOCH":           uint64(32),
		"SLOT_DURATION_MS":          uint64(12000),
		"ATTESTATION_DUE_BPS_GLOAS": uint64(2500),
	})

	require.Equal(t, 4*time.Second, s.attestationDelay(0))
	require.Equal(t, 4*time.Second, s.attestationDelay(1<<40))
}
