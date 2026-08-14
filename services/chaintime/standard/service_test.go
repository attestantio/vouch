// Copyright © 2020 Attestant Limited.
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

package standard_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/chaintime/standard"
	testlogger "github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

type mutableSpecProvider struct {
	mu       sync.RWMutex
	response *api.Response[map[string]any]
	err      error
	calls    atomic.Uint64
	entered  chan struct{}
	release  chan struct{}
}

func (s *mutableSpecProvider) Spec(_ context.Context, _ *api.SpecOpts) (*api.Response[map[string]any], error) {
	s.calls.Add(1)
	s.mu.RLock()
	response := s.response
	err := s.err
	entered := s.entered
	release := s.release
	s.mu.RUnlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	if err != nil {
		return nil, err
	}

	return response, nil
}

func newMutableSpecProvider(spec map[string]any) *mutableSpecProvider {
	return &mutableSpecProvider{
		response: &api.Response[map[string]any]{Data: spec},
	}
}

func (s *mutableSpecProvider) setSpec(spec map[string]any) {
	s.mu.Lock()
	s.response = &api.Response[map[string]any]{Data: spec}
	s.mu.Unlock()
}

func (s *mutableSpecProvider) setError(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func createMutableSpecService(t testing.TB, specProvider *mutableSpecProvider) chaintime.Service {
	t.Helper()

	service, err := standard.New(context.Background(),
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standard.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	return service
}

func TestService(t *testing.T) {
	genesisTime := time.Now()
	mockGenesisProvider := mock.NewGenesisProvider(genesisTime)
	mockSpecProvider := mock.NewSpecProvider()

	tests := []struct {
		name   string
		params []standard.Parameter
		err    string
	}{
		{
			name: "GenesisProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithSpecProvider(mockSpecProvider),
			},
			err: "problem with parameters: no genesis provider specified",
		},
		{
			name: "SpecProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithGenesisProvider(mockGenesisProvider),
			},
			err: "problem with parameters: no spec provider specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithGenesisProvider(mockGenesisProvider),
				standard.WithSpecProvider(mockSpecProvider),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := standard.New(context.Background(), test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func createMockService(genesisTime time.Time) (chaintime.Service, error) {
	mockGenesisProvider := mock.NewGenesisProvider(genesisTime)
	mockSpecProvider := mock.NewSpecProvider()
	s, err := standard.New(context.Background(),
		standard.WithGenesisProvider(mockGenesisProvider),
		standard.WithSpecProvider(mockSpecProvider),
	)
	return s, err
}

func TestGenesisTime(t *testing.T) {
	genesisTime := time.Now()

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, genesisTime, s.GenesisTime())
}

func TestStartOfSlot(t *testing.T) {
	slotDuration := 12 * time.Second
	genesisTime := time.Now()

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, genesisTime, s.StartOfSlot(0))
	require.Equal(t, genesisTime.Add(1000*slotDuration), s.StartOfSlot(1000))
}

func TestStartOfEpoch(t *testing.T) {
	slotDuration := 12 * time.Second
	slotsPerEpoch := uint64(32)
	genesisTime := time.Now()

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, genesisTime, s.StartOfEpoch(0))
	require.Equal(t, genesisTime.Add(time.Duration(1000*slotsPerEpoch)*slotDuration), s.StartOfEpoch(1000))
}

func TestCurrentSlot(t *testing.T) {
	slotDuration := 12 * time.Second
	genesisTime := time.Now().Add(-5 * slotDuration)

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, phase0.Slot(5), s.CurrentSlot())
}

func TestCurrentSlotPreGenesis(t *testing.T) {
	genesisTime := time.Now().Add(3 * time.Hour)

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, phase0.Slot(0), s.CurrentSlot())
}

func TestCurrentEpoch(t *testing.T) {
	slotDuration := 12 * time.Second
	slotsPerEpoch := uint64(32)
	genesisTime := time.Now().Add(time.Duration(int64(-2)*int64(slotsPerEpoch)) * slotDuration)

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, phase0.Epoch(2), s.CurrentEpoch())
}

func TestCurrentEpochPreGenesis(t *testing.T) {
	genesisTime := time.Now().Add(3 * time.Hour)

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, phase0.Epoch(0), s.CurrentEpoch())
}

func TestSlotToEpoch(t *testing.T) {
	tests := []struct {
		name  string
		slot  phase0.Slot
		epoch phase0.Epoch
	}{
		{
			name:  "ZeroFirstSlot",
			slot:  0,
			epoch: 0,
		},
		{
			name:  "ZeroLastSlot",
			slot:  31,
			epoch: 0,
		},
		{
			name:  "OneFirstSlot",
			slot:  32,
			epoch: 1,
		},
	}

	genesisTime := time.Now()

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			epoch := s.SlotToEpoch(test.slot)
			assert.Equal(t, test.epoch, epoch)
		})
	}
}

func TestFirstSlotOfEpoch(t *testing.T) {
	tests := []struct {
		name  string
		epoch phase0.Epoch
		slot  phase0.Slot
	}{
		{
			name:  "Zero",
			epoch: 0,
			slot:  0,
		},
		{
			name:  "One",
			epoch: 1,
			slot:  32,
		},
		{
			name:  "OneThousand",
			epoch: 1000,
			slot:  32000,
		},
	}

	genesisTime := time.Now()

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			slot := s.FirstSlotOfEpoch(test.epoch)
			assert.Equal(t, test.slot, slot)
		})
	}
}

func TestHardForkEpochUsesConstructionSchedule(t *testing.T) {
	ctx := context.Background()
	specProvider := newMutableSpecProvider(map[string]any{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
		"GLOAS_FORK_EPOCH": uint64(2048),
	})
	service := createMutableSpecService(t, specProvider)

	specProvider.setError(errors.New("spec unavailable"))

	require.Equal(t, phase0.Epoch(2048), service.HardForkEpoch(ctx, "GLOAS_FORK_EPOCH"))
}

func TestHardForkEpochRetainsDiscoveredFork(t *testing.T) {
	ctx := context.Background()
	specProvider := newMutableSpecProvider(map[string]any{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
	})
	service := createMutableSpecService(t, specProvider)

	specProvider.setSpec(map[string]any{
		"SECONDS_PER_SLOT":  12 * time.Second,
		"SLOTS_PER_EPOCH":   uint64(32),
		"FUTURE_FORK_EPOCH": uint64(2048),
	})
	require.Equal(t, phase0.Epoch(2048), service.HardForkEpoch(ctx, "FUTURE_FORK_EPOCH"))

	specProvider.setError(errors.New("spec unavailable"))
	require.Equal(t, phase0.Epoch(2048), service.HardForkEpoch(ctx, "FUTURE_FORK_EPOCH"))
}

func TestHardForkEpochRecognisesMalformedConstructionValue(t *testing.T) {
	ctx := context.Background()
	oldLogger := zerologger.Logger
	oldLogLevel := zerolog.GlobalLevel()
	t.Cleanup(func() {
		zerologger.Logger = oldLogger
		zerolog.SetGlobalLevel(oldLogLevel)
	})
	logCapture := testlogger.NewLogCapture()
	specProvider := newMutableSpecProvider(map[string]any{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
		"GLOAS_FORK_EPOCH": "2048",
	})
	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.TraceLevel),
		standard.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standard.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	require.Equal(t, phase0.Epoch(^uint64(0)), service.HardForkEpoch(ctx, "GLOAS_FORK_EPOCH"))
	require.Equal(t, uint64(1), specProvider.calls.Load())
	require.True(t, logCapture.HasLog(map[string]any{
		"error": "GLOAS_FORK_EPOCH is not a uint64",
	}))
}

func TestHardForkEpochRetainsMalformedRefreshedValue(t *testing.T) {
	ctx := context.Background()
	specProvider := newMutableSpecProvider(map[string]any{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
	})
	service := createMutableSpecService(t, specProvider)

	specProvider.setSpec(map[string]any{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
		"GLOAS_FORK_EPOCH": "2048",
	})
	require.Equal(t, phase0.Epoch(^uint64(0)), service.HardForkEpoch(ctx, "GLOAS_FORK_EPOCH"))

	specProvider.setError(errors.New("spec unavailable"))
	require.Equal(t, phase0.Epoch(^uint64(0)), service.HardForkEpoch(ctx, "GLOAS_FORK_EPOCH"))
	require.Equal(t, uint64(2), specProvider.calls.Load())
}

func TestHardForkEpochRetainsValidValueWhenRefreshIsMalformed(t *testing.T) {
	ctx := context.Background()
	specProvider := newMutableSpecProvider(map[string]any{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
		"GLOAS_FORK_EPOCH": uint64(2048),
	})
	service := createMutableSpecService(t, specProvider)

	specProvider.setSpec(map[string]any{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
		"GLOAS_FORK_EPOCH": "2048",
	})
	require.Equal(t, phase0.Epoch(^uint64(0)), service.HardForkEpoch(ctx, "MISSING_FORK_EPOCH"))
	require.Equal(t, phase0.Epoch(2048), service.HardForkEpoch(ctx, "GLOAS_FORK_EPOCH"))
	require.Equal(t, uint64(2), specProvider.calls.Load())
}

func TestHardForkEpochReturnsFarFutureWhenUnavailable(t *testing.T) {
	ctx := context.Background()
	specProvider := newMutableSpecProvider(map[string]any{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
	})
	service := createMutableSpecService(t, specProvider)
	specProvider.setError(errors.New("spec unavailable"))

	require.Equal(t, phase0.Epoch(^uint64(0)), service.HardForkEpoch(ctx, "MISSING_FORK_EPOCH"))
}

func TestHardForkEpochReadersContinueDuringRefresh(t *testing.T) {
	ctx := context.Background()
	specProvider := newMutableSpecProvider(map[string]any{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
		"GLOAS_FORK_EPOCH": uint64(2048),
	})
	service := createMutableSpecService(t, specProvider)

	specProvider.entered = make(chan struct{}, 1)
	specProvider.release = make(chan struct{})
	refreshed := make(chan phase0.Epoch, 1)
	go func() {
		refreshed <- service.HardForkEpoch(ctx, "MISSING_FORK_EPOCH")
	}()
	<-specProvider.entered

	known := make(chan phase0.Epoch, 1)
	go func() {
		known <- service.HardForkEpoch(ctx, "GLOAS_FORK_EPOCH")
	}()
	select {
	case epoch := <-known:
		require.Equal(t, phase0.Epoch(2048), epoch)
	case <-time.After(time.Second):
		t.Fatal("known fork lookup blocked during refresh")
	}

	close(specProvider.release)
	require.Equal(t, phase0.Epoch(^uint64(0)), <-refreshed)
}
