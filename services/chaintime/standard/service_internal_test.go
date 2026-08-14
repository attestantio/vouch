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
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

type internalSpecProvider struct {
	spec  map[string]any
	err   error
	calls atomic.Uint64
}

func (s *internalSpecProvider) Spec(_ context.Context, _ *api.SpecOpts) (*api.Response[map[string]any], error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	return &api.Response[map[string]any]{Data: s.spec}, nil
}

type blockingInternalSpecProvider struct {
	entered chan struct{}
	release chan struct{}
}

func (s *blockingInternalSpecProvider) Spec(_ context.Context, _ *api.SpecOpts) (*api.Response[map[string]any], error) {
	close(s.entered)
	<-s.release

	return &api.Response[map[string]any]{Data: make(map[string]any)}, nil
}

func TestRefreshForkScheduleWaiterHonoursCancellation(t *testing.T) {
	ctx := context.Background()
	provider := &blockingInternalSpecProvider{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	schedule := forkSchedule{
		epochs:    make(map[string]phase0.Epoch),
		malformed: make(map[string]struct{}),
	}
	service := &Service{
		genesisTime:   time.Now(),
		slotDuration:  12 * time.Second,
		slotsPerEpoch: 32,
		specProvider:  provider,
	}
	service.forkSchedule.Store(&schedule)

	leaderDone := make(chan error, 1)
	go func() {
		leaderDone <- service.refreshForkSchedule(ctx, nil)
	}()
	<-provider.entered
	t.Cleanup(func() {
		close(provider.release)
		require.NoError(t, <-leaderDone)
	})

	waiterCtx, cancel := context.WithCancel(ctx)
	cancel()
	waiterDone := make(chan error, 1)
	go func() {
		waiterDone <- service.refreshForkSchedule(waiterCtx, nil)
	}()

	select {
	case err := <-waiterDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("canceled refresh waiter remained blocked")
	}
}

func TestRefreshForkScheduleSharesCompletedGeneration(t *testing.T) {
	ctx := context.Background()
	provider := &internalSpecProvider{spec: make(map[string]any)}
	schedule := forkSchedule{
		epochs:    make(map[string]phase0.Epoch),
		malformed: make(map[string]struct{}),
	}
	generation := &forkScheduleGeneration{}
	service := &Service{
		genesisTime:   time.Now(),
		slotDuration:  12 * time.Second,
		slotsPerEpoch: 32,
		specProvider:  provider,
	}
	service.forkSchedule.Store(&schedule)
	service.forkScheduleGeneration.Store(generation)

	require.NoError(t, service.refreshForkSchedule(ctx, generation))
	require.NoError(t, service.refreshForkSchedule(ctx, generation))
	require.Equal(t, uint64(1), provider.calls.Load())
}

func TestRefreshForkScheduleCoalescesGeneration(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name        string
		spec        map[string]any
		providerErr error
		expected    map[string]phase0.Epoch
		err         string
	}{
		{
			name:     "Missing",
			spec:     make(map[string]any),
			expected: make(map[string]phase0.Epoch),
		},
		{
			name: "Discovery",
			spec: map[string]any{
				"FUTURE_FORK_EPOCH": uint64(2048),
			},
			expected: map[string]phase0.Epoch{
				"FUTURE_FORK_EPOCH": 2048,
			},
		},
		{
			name:        "Failure",
			spec:        make(map[string]any),
			providerErr: errors.New("spec unavailable"),
			expected:    make(map[string]phase0.Epoch),
			err:         "failed to obtain spec: spec unavailable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &internalSpecProvider{spec: test.spec, err: test.providerErr}
			schedule := forkSchedule{
				epochs:    make(map[string]phase0.Epoch),
				malformed: make(map[string]struct{}),
			}
			generation := &forkScheduleGeneration{}
			service := &Service{
				genesisTime:   time.Now(),
				slotDuration:  12 * time.Second,
				slotsPerEpoch: 32,
				specProvider:  provider,
			}
			service.forkSchedule.Store(&schedule)
			service.forkScheduleGeneration.Store(generation)

			const readers = 16
			results := make(chan error, readers)
			for range readers {
				go func() {
					results <- service.refreshForkSchedule(ctx, generation)
				}()
			}
			for range readers {
				err := <-results
				if test.err == "" {
					require.NoError(t, err)
				} else {
					require.EqualError(t, err, test.err)
				}
			}

			require.Equal(t, uint64(1), provider.calls.Load())
			require.Equal(t, test.expected, service.forkSchedule.Load().epochs)
		})
	}
}

func TestRefreshForkSchedule(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		spec     map[string]any
		expected map[string]phase0.Epoch
		same     bool
	}{
		{
			name: "Unchanged",
			spec: map[string]any{
				"GLOAS_FORK_EPOCH": uint64(2048),
			},
			expected: map[string]phase0.Epoch{
				"GLOAS_FORK_EPOCH": phase0.Epoch(2048),
			},
			same: true,
		},
		{
			name: "Omitted",
			spec: make(map[string]any),
			expected: map[string]phase0.Epoch{
				"GLOAS_FORK_EPOCH": phase0.Epoch(2048),
			},
			same: true,
		},
		{
			name: "Added",
			spec: map[string]any{
				"GLOAS_FORK_EPOCH":  uint64(2048),
				"FUTURE_FORK_EPOCH": uint64(4096),
			},
			expected: map[string]phase0.Epoch{
				"GLOAS_FORK_EPOCH":  phase0.Epoch(2048),
				"FUTURE_FORK_EPOCH": phase0.Epoch(4096),
			},
		},
		{
			name: "Changed",
			spec: map[string]any{
				"GLOAS_FORK_EPOCH": uint64(4096),
			},
			expected: map[string]phase0.Epoch{
				"GLOAS_FORK_EPOCH": phase0.Epoch(4096),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schedule := forkSchedule{
				epochs: map[string]phase0.Epoch{
					"GLOAS_FORK_EPOCH": phase0.Epoch(2048),
				},
				malformed: make(map[string]struct{}),
			}
			service := &Service{
				genesisTime:   time.Now(),
				slotDuration:  12 * time.Second,
				slotsPerEpoch: 32,
				specProvider:  &internalSpecProvider{spec: test.spec},
			}
			service.forkSchedule.Store(&schedule)
			before := service.forkSchedule.Load()

			require.NoError(t, service.refreshForkSchedule(ctx, nil))
			after := service.forkSchedule.Load()
			if test.same {
				require.Same(t, before, after)
			} else {
				require.NotSame(t, before, after)
			}
			require.Equal(t, test.expected, after.epochs)
		})
	}
}

func TestRefreshForkScheduleRejectsActivatedForkChange(t *testing.T) {
	ctx := context.Background()
	schedule := forkSchedule{
		epochs: map[string]phase0.Epoch{
			"GLOAS_FORK_EPOCH": 1,
		},
		malformed: make(map[string]struct{}),
	}
	service := &Service{
		genesisTime:   time.Now().Add(-100 * 32 * 12 * time.Second),
		slotDuration:  12 * time.Second,
		slotsPerEpoch: 32,
		specProvider: &internalSpecProvider{spec: map[string]any{
			"GLOAS_FORK_EPOCH": uint64(4096),
		}},
	}
	service.forkSchedule.Store(&schedule)
	before := service.forkSchedule.Load()

	require.NoError(t, service.refreshForkSchedule(ctx, nil))
	after := service.forkSchedule.Load()
	require.Same(t, before, after)
	require.Equal(t, phase0.Epoch(1), after.epochs["GLOAS_FORK_EPOCH"])
}

func TestRefreshForkScheduleRejectsRollback(t *testing.T) {
	ctx := context.Background()
	schedule := forkSchedule{
		epochs: map[string]phase0.Epoch{
			"GLOAS_FORK_EPOCH": 4096,
		},
		malformed: make(map[string]struct{}),
	}
	service := &Service{
		genesisTime:   time.Now().Add(-100 * 32 * 12 * time.Second),
		slotDuration:  12 * time.Second,
		slotsPerEpoch: 32,
		specProvider: &internalSpecProvider{spec: map[string]any{
			"GLOAS_FORK_EPOCH": uint64(1),
		}},
	}
	service.forkSchedule.Store(&schedule)
	before := service.forkSchedule.Load()

	require.NoError(t, service.refreshForkSchedule(ctx, nil))
	after := service.forkSchedule.Load()
	require.Same(t, before, after)
	require.Equal(t, phase0.Epoch(4096), after.epochs["GLOAS_FORK_EPOCH"])
}
