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
	"testing/synctest"
	"time"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/chaintime"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// fixedSpecProvider serves a fixed spec, so each test controls exactly which keys the node serves.
type fixedSpecProvider map[string]any

func (s fixedSpecProvider) Spec(_ context.Context, _ *api.SpecOpts) (*api.Response[map[string]any], error) {
	return &api.Response[map[string]any]{Data: s}, nil
}

func newStaticDelayService(t *testing.T, spec consensusclient.SpecProvider, params ...Parameter) (*Service, error) {
	t.Helper()
	ctx := context.Background()

	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(spec),
	)
	require.NoError(t, err)

	return New(ctx, append([]Parameter{
		WithLogLevel(zerolog.Disabled),
		WithSpecProvider(spec),
		WithAttestationPoolProvider(mock.NewAttestationPoolProvider()),
		WithBeaconBlockHeadersProvider(mock.NewBeaconBlockHeadersProvider()),
		WithChainTime(chainTime),
		WithAttesterDelay(time.Second),
	}, params...)...)
}

const (
	gloasForkEpoch = 5
	slotsPerEpoch  = 32
	farFutureEpoch = chaintime.FarFutureEpoch
)

// TestAttestationDelay confirms that the base delay is chosen from the duty's slot, so a process
// running across the fork switches to the Gloas deadline at the first Gloas slot.
func TestAttestationDelay(t *testing.T) {
	spec := fixedSpecProvider{
		"SECONDS_PER_SLOT":          12 * time.Second,
		"SLOTS_PER_EPOCH":           uint64(slotsPerEpoch),
		"SLOT_DURATION_MS":          uint64(12000),
		"ATTESTATION_DUE_BPS_GLOAS": uint64(2500),
		"GLOAS_FORK_EPOCH":          uint64(gloasForkEpoch),
	}
	s, err := newStaticDelayService(t, spec)
	require.NoError(t, err)

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

// TestMaxAttestationDelayOverride confirms the controller's override moves the pre-Gloas deadline
// only, as the controller ignores it on Gloas slots.
func TestMaxAttestationDelayOverride(t *testing.T) {
	s, err := newStaticDelayService(t, fixedSpecProvider{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(slotsPerEpoch),
		"GLOAS_FORK_EPOCH": uint64(gloasForkEpoch),
	}, WithMaxAttestationDelay(6*time.Second))
	require.NoError(t, err)

	require.Equal(t, 6*time.Second, s.attestationDelay(slotsPerEpoch*gloasForkEpoch-1))
	require.Equal(t, 3*time.Second, s.attestationDelay(slotsPerEpoch*gloasForkEpoch))
}

// TestGloasAttestationDelay confirms the Gloas deadline follows the spec, and falls back to the
// Gloas deadline itself when the node does not serve a usable value.
func TestGloasAttestationDelay(t *testing.T) {
	tests := []struct {
		name     string
		spec     map[string]any
		expected time.Duration
	}{
		{
			name: "GloasKeysMissing",
			spec: map[string]any{
				"SECONDS_PER_SLOT": 12 * time.Second,
			},
			expected: 3 * time.Second,
		},
		{
			name: "CustomSlotDuration",
			spec: map[string]any{
				"SECONDS_PER_SLOT":          6 * time.Second,
				"SLOT_DURATION_MS":          uint64(6000),
				"ATTESTATION_DUE_BPS_GLOAS": uint64(2500),
			},
			expected: 1500 * time.Millisecond,
		},
		{
			name: "CustomDueBPS",
			spec: map[string]any{
				"SECONDS_PER_SLOT":          12 * time.Second,
				"SLOT_DURATION_MS":          uint64(12000),
				"ATTESTATION_DUE_BPS_GLOAS": uint64(2000),
			},
			expected: 2400 * time.Millisecond,
		},
		{
			name: "DueBPSOutOfRange",
			spec: map[string]any{
				"SECONDS_PER_SLOT":          12 * time.Second,
				"SLOT_DURATION_MS":          uint64(12000),
				"ATTESTATION_DUE_BPS_GLOAS": uint64(10001),
			},
			expected: 3 * time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, gloasDelay, err := obtainAttestationDelays(test.spec, 0)
			require.NoError(t, err)
			require.Equal(t, test.expected, gloasDelay)
		})
	}
}

// TestAttestationDelayWithoutGloas confirms that a chain with no Gloas fork scheduled keeps the
// pre-Gloas deadline on every slot.
func TestAttestationDelayWithoutGloas(t *testing.T) {
	s, err := newStaticDelayService(t, fixedSpecProvider{
		"SECONDS_PER_SLOT":          12 * time.Second,
		"SLOTS_PER_EPOCH":           uint64(32),
		"SLOT_DURATION_MS":          uint64(12000),
		"ATTESTATION_DUE_BPS_GLOAS": uint64(2500),
	})
	require.NoError(t, err)

	require.Equal(t, 4*time.Second, s.attestationDelay(0))
	require.Equal(t, 4*time.Second, s.attestationDelay(1<<40))
}

// TestGloasForkEpoch confirms the fork epoch comes from chaintime, which treats a missing or
// malformed value as far future, as the controller does.
func TestGloasForkEpoch(t *testing.T) {
	tests := []struct {
		name     string
		fork     any
		expected phase0.Epoch
	}{
		{name: "Scheduled", fork: uint64(5), expected: 5},
		{name: "FromGenesis", fork: uint64(0)},
		{name: "Missing", expected: farFutureEpoch},
		{name: "FarFuture", fork: uint64(farFutureEpoch), expected: farFutureEpoch},
		{name: "Malformed", fork: "5", expected: farFutureEpoch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := fixedSpecProvider{
				"SECONDS_PER_SLOT": 12 * time.Second,
				"SLOTS_PER_EPOCH":  uint64(slotsPerEpoch),
			}
			if test.fork != nil {
				spec["GLOAS_FORK_EPOCH"] = test.fork
			}
			s, err := newStaticDelayService(t, spec)
			require.NoError(t, err)
			require.Equal(t, test.expected, s.gloasForkEpoch)
		})
	}
}

func TestPreGloasAttestationDelay(t *testing.T) {
	tests := []struct {
		name      string
		intervals any
	}{
		{name: "Missing"},
		{name: "Zero", intervals: uint64(0)},
		{name: "Four", intervals: uint64(4)},
		{name: "Two", intervals: uint64(2)},
		{name: "Malformed", intervals: "3"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := map[string]any{"SECONDS_PER_SLOT": 12 * time.Second}
			if test.intervals != nil {
				spec["INTERVALS_PER_SLOT"] = test.intervals
			}
			preGloasDelay, _, err := obtainAttestationDelays(spec, farFutureEpoch)
			require.NoError(t, err)
			require.Equal(t, 4*time.Second, preGloasDelay)
		})
	}
}

func TestGloasSlotDurationMismatch(t *testing.T) {
	const mismatch = "SLOT_DURATION_MS 6s differs from SECONDS_PER_SLOT 12s; chaintime does not support changing slot duration"
	tests := []struct {
		name string
		fork phase0.Epoch
		err  string
	}{
		{name: "FromGenesis", fork: 0, err: mismatch},
		{name: "Scheduled", fork: gloasForkEpoch, err: mismatch},
		{name: "NotScheduled", fork: farFutureEpoch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := map[string]any{
				"SECONDS_PER_SLOT": 12 * time.Second,
				"SLOT_DURATION_MS": uint64(6000),
			}
			_, _, err := obtainAttestationDelays(spec, test.fork)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestShouldAttestDeadline(t *testing.T) {
	tests := []struct {
		name     string
		slot     phase0.Slot
		deadline time.Duration
	}{
		{name: "LastSlotBeforeGloas", slot: slotsPerEpoch*gloasForkEpoch - 1, deadline: 4 * time.Second},
		{name: "FirstGloasSlot", slot: slotsPerEpoch * gloasForkEpoch, deadline: 3 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				s, err := newStaticDelayService(t, fixedSpecProvider{
					"SECONDS_PER_SLOT": 12 * time.Second,
					"SLOTS_PER_EPOCH":  uint64(slotsPerEpoch),
					"GLOAS_FORK_EPOCH": uint64(gloasForkEpoch),
				})
				require.NoError(t, err)
				duty, err := attester.NewDuty(ctx, test.slot, 1,
					[]phase0.ValidatorIndex{1}, []phase0.CommitteeIndex{0}, []uint64{0},
					map[phase0.CommitteeIndex]uint64{0: 1},
				)
				require.NoError(t, err)
				expected := s.chainTime.StartOfSlot(test.slot).Add(test.deadline + time.Second)

				require.True(t, s.ShouldAttest(ctx, duty))
				require.Equal(t, expected, time.Now())
			})
		})
	}
}

func TestAttestationDelaySpecValues(t *testing.T) {
	tests := []struct {
		name string
		key  string
		raw  any
		err  string
	}{
		{name: "SecondsMissing", err: "failed to obtain SECONDS_PER_SLOT"},
		{name: "SecondsMalformed", key: "SECONDS_PER_SLOT", raw: uint64(12), err: "seconds per slot not a duration"},
		{name: "SlotDurationZero", key: "SLOT_DURATION_MS", raw: uint64(0)},
		{name: "SlotDurationMalformed", key: "SLOT_DURATION_MS", raw: "12000"},
		{name: "DueBPSZero", key: "ATTESTATION_DUE_BPS_GLOAS", raw: uint64(0)},
		{name: "DueBPSMalformed", key: "ATTESTATION_DUE_BPS_GLOAS", raw: "2500"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := map[string]any{"SECONDS_PER_SLOT": 12 * time.Second}
			if test.key == "" {
				delete(spec, "SECONDS_PER_SLOT")
			} else {
				spec[test.key] = test.raw
			}
			preGloasDelay, gloasDelay, err := obtainAttestationDelays(spec, 0)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, 4*time.Second, preGloasDelay)
			require.Equal(t, 3*time.Second, gloasDelay)
		})
	}
}

// failingSpecProvider serves the spec a fixed number of times, then fails.
type failingSpecProvider struct {
	fixedSpecProvider
	remaining int
}

func (s *failingSpecProvider) Spec(ctx context.Context, opts *api.SpecOpts) (*api.Response[map[string]any], error) {
	if s.remaining == 0 {
		return nil, errors.New("spec unavailable")
	}
	s.remaining--

	return s.fixedSpecProvider.Spec(ctx, opts)
}

func TestNewSpecFetchFailure(t *testing.T) {
	tests := []struct {
		name    string
		fork    any
		fetches int
		err     string
	}{
		// Chaintime construction consumes the first fetch.
		{name: "Spec", fetches: 1, err: "spec unavailable"},
		{name: "ForkLookup", fork: uint64(gloasForkEpoch), fetches: 2, err: "GLOAS_FORK_EPOCH lookup returned 18446744073709551615 but the spec serves 5"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &failingSpecProvider{
				fixedSpecProvider: fixedSpecProvider{
					"SECONDS_PER_SLOT": 12 * time.Second,
					"SLOTS_PER_EPOCH":  uint64(slotsPerEpoch),
				},
				remaining: test.fetches,
			}
			if test.fork != nil {
				provider.fixedSpecProvider["GLOAS_FORK_EPOCH"] = test.fork
			}
			_, err := newStaticDelayService(t, provider)
			require.EqualError(t, err, test.err)
		})
	}
}
