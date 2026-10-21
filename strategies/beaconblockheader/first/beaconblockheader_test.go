// Copyright © 2024 - 2026 Attestant Limited.
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

package first_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/strategies/beaconblockheader/first"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestBeaconBlockHeadersCountsEmptyResponseAsClientFailure checks that a response without a header is not
// recorded as a successful client call.
func TestBeaconBlockHeadersCountsEmptyResponseAsClientFailure(t *testing.T) {
	monitor := &clientOperationRecorder{}
	s, err := first.New(context.Background(),
		first.WithLogLevel(zerolog.Disabled),
		first.WithTimeout(2*time.Second),
		first.WithClientMonitor(monitor),
		first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
			"empty": &emptyHeaderProvider{},
		}),
	)
	require.NoError(t, err)

	_, err = s.BeaconBlockHeader(context.Background(), &api.BeaconBlockHeaderOpts{Block: "1"})
	require.ErrorContains(t, err, "no beacon block header")
	require.Equal(t, []bool{false}, monitor.succeeded)
}

type clientOperationRecorder struct {
	mu        sync.Mutex
	succeeded []bool
}

func (m *clientOperationRecorder) ClientOperation(_ string, _ string, succeeded bool, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.succeeded = append(m.succeeded, succeeded)
}

func (*clientOperationRecorder) StrategyOperation(string, string, string, time.Duration) {}

type emptyHeaderProvider struct{}

func (*emptyHeaderProvider) BeaconBlockHeader(context.Context, *api.BeaconBlockHeaderOpts) (*api.Response[*apiv1.BeaconBlockHeader], error) {
	return &api.Response[*apiv1.BeaconBlockHeader]{}, nil
}

type headerErrorProvider struct {
	err error
}

func (p *headerErrorProvider) BeaconBlockHeader(context.Context, *api.BeaconBlockHeaderOpts) (*api.Response[*apiv1.BeaconBlockHeader], error) {
	return nil, p.err
}

func TestBeaconBlockHeaders(t *testing.T) {
	notFound := &api.Error{StatusCode: 404}
	serviceUnavailable := &api.Error{StatusCode: 503}
	errConnectionRefused := errors.New("connection refused")
	tests := []struct {
		name            string
		params          []first.Parameter
		blockID         string
		beaconBlockRoot phase0.Root
		err             string
		errIs           error
		errIsNot        error
		errContains     string
		// answered is true when every provider answers at once, so the strategy must not wait for its timeout.
		answered bool
	}{
		{
			name: "Good",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"good": mock.NewBeaconBlockHeadersProvider(),
				}),
			},
			blockID: "1",
			beaconBlockRoot: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
		{
			name: "Timeout",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"sleepy": mock.NewSleepyBeaconBlockHeadersProvider(5*time.Second, mock.NewBeaconBlockHeadersProvider()),
				}),
			},
			blockID: "1",
			beaconBlockRoot: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
			err:   "failed to obtain beacon block header before timeout",
			errIs: first.ErrBeaconBlockHeaderTimeout,
		},
		{
			name: "GoodMixed",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"error":  mock.NewErroringBeaconBlockHeadersProvider(),
					"sleepy": mock.NewSleepyBeaconBlockHeadersProvider(time.Second, mock.NewBeaconBlockHeadersProvider()),
				}),
			},
			blockID: "1",
			beaconBlockRoot: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
		{
			name: "AllNotFound",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"missing1": &headerErrorProvider{err: notFound},
					"missing2": &headerErrorProvider{err: notFound},
				}),
			},
			blockID:  "1",
			errIs:    notFound,
			answered: true,
		},
		{
			name: "NotFoundAndProviderDeadline",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"missing":   &headerErrorProvider{err: notFound},
					"timed-out": &headerErrorProvider{err: context.DeadlineExceeded},
				}),
			},
			blockID:     "1",
			errIs:       first.ErrBeaconBlockHeaderTimeout,
			errIsNot:    notFound,
			errContains: "timed-out",
			answered:    true,
		},
		{
			name: "ProviderFailureThenStrategyTimeout",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"offline": &headerErrorProvider{err: errConnectionRefused},
					"sleepy":  mock.NewSleepyBeaconBlockHeadersProvider(5*time.Second, mock.NewBeaconBlockHeadersProvider()),
				}),
			},
			blockID:     "1",
			errIs:       first.ErrBeaconBlockHeaderTimeout,
			errContains: "offline",
		},
		{
			name: "NotFoundThenStrategyTimeout",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"missing": &headerErrorProvider{err: notFound},
					"sleepy":  mock.NewSleepyBeaconBlockHeadersProvider(5*time.Second, mock.NewBeaconBlockHeadersProvider()),
				}),
			},
			blockID:  "1",
			errIs:    first.ErrBeaconBlockHeaderTimeout,
			errIsNot: notFound,
		},
		{
			name: "ProviderFailure",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"offline": &headerErrorProvider{err: errConnectionRefused},
				}),
			},
			blockID:  "1",
			errIs:    errConnectionRefused,
			answered: true,
		},
		{
			name: "NotFoundAndProviderFailure",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"missing": &headerErrorProvider{err: notFound},
					"offline": &headerErrorProvider{err: errConnectionRefused},
				}),
			},
			blockID:  "1",
			errIs:    errConnectionRefused,
			errIsNot: notFound,
			answered: true,
		},
		{
			name: "NotFoundAndServiceUnavailable",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"missing":     &headerErrorProvider{err: notFound},
					"unavailable": &headerErrorProvider{err: serviceUnavailable},
				}),
			},
			blockID:  "1",
			errIs:    serviceUnavailable,
			errIsNot: notFound,
			answered: true,
		},
	}

	for _, test := range tests {
		run := func(t *testing.T) {
			t.Helper()
			s, err := first.New(context.Background(), test.params...)
			require.NoError(t, err)

			started := time.Now()
			root, err := s.BeaconBlockHeader(context.Background(), &api.BeaconBlockHeaderOpts{
				Block: test.blockID,
			})
			switch {
			case test.err != "":
				require.EqualError(t, err, test.err)
			case test.errIs == nil:
				require.NoError(t, err)
				require.NotNil(t, root)
			}
			if test.errIs != nil {
				require.ErrorIs(t, err, test.errIs)
			}
			if test.errIsNot != nil {
				require.NotErrorIs(t, err, test.errIsNot)
			}
			if test.errContains != "" {
				require.ErrorContains(t, err, test.errContains)
			}
			if test.answered {
				require.Less(t, time.Since(started), time.Second)
			}
		}
		t.Run(test.name, func(t *testing.T) {
			if test.answered {
				// The fake clock makes the elapsed-time check exact; other rows leave sleeping providers behind.
				synctest.Test(t, run)
			} else {
				run(t)
			}
		})
	}
}
