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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/chaintime"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/attestantio/vouch/services/scheduler"
	mockscheduler "github.com/attestantio/vouch/services/scheduler/mock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// steppedChainTime reports a current epoch set by the test instead of the wall clock.
type steppedChainTime struct {
	chaintime.Service
	epoch atomic.Uint64
}

func (c *steppedChainTime) CurrentEpoch() phase0.Epoch {
	return phase0.Epoch(c.epoch.Load())
}

func (c *steppedChainTime) CurrentSlot() phase0.Slot {
	return c.FirstSlotOfEpoch(c.CurrentEpoch())
}

// tickerScheduler captures the epoch ticker and records one-off job names.
type tickerScheduler struct {
	scheduler.Service
	mu         sync.Mutex
	jobs       []string
	tickerTime scheduler.RuntimeFunc
	tickerJob  scheduler.JobFunc
}

func (s *tickerScheduler) ScheduleJob(_ context.Context, _ string, name string, _ time.Time, _ scheduler.JobFunc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs = append(s.jobs, name)

	return nil
}

func (s *tickerScheduler) SchedulePeriodicJob(_ context.Context, _ string, name string, runtimeFunc scheduler.RuntimeFunc, jobFunc scheduler.JobFunc) error {
	if name == "Epoch ticker" {
		s.tickerTime = runtimeFunc
		s.tickerJob = jobFunc
	}

	return nil
}

func (s *tickerScheduler) scheduled(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, job := range s.jobs {
		if job == name {
			return true
		}
	}

	return false
}

// An epoch timer can fire a few milliseconds before the wall clock reaches the epoch start.
// The ticker must still do that epoch's work, including preparing the following epoch.
func TestEpochTickerEarlyFirstTick(t *testing.T) {
	ctx := context.Background()
	specProvider := &seedLookaheadSpecProvider{SpecProvider: mock.NewSpecProvider()}
	baseChainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	chainTime := &steppedChainTime{Service: baseChainTime}
	sched := &tickerScheduler{Service: mockscheduler.New()}

	newProposerPreferencesController(t, &recordingEventsProvider{},
		WithChainTimeService(chainTime),
		WithScheduler(sched),
	)
	require.NotNil(t, sched.tickerJob)

	// Run the ticker the way the periodic scheduler does, for up to a few iterations.
	// The first tick for epoch 1 fires while the clock still reads epoch 0, and the
	// clock reaches epoch 1 while that tick is running.
	runtime, err := sched.tickerTime(ctx)
	require.NoError(t, err)
	require.Equal(t, chainTime.StartOfEpoch(1), runtime)
	sched.tickerJob(ctx)
	chainTime.epoch.Store(1)
	for range 3 {
		runtime, err = sched.tickerTime(ctx)
		require.NoError(t, err)
		if runtime.After(chainTime.StartOfEpoch(1)) {
			break
		}
		sched.tickerJob(ctx)
	}

	require.True(t, sched.scheduled("Prepare for epoch 2"), "epoch 1 tick must prepare epoch 2")
	require.Equal(t, chainTime.StartOfEpoch(2), runtime)
}
