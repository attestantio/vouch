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
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/strategies/beaconblockheader/first"
	"github.com/attestantio/vouch/util"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestBeaconBlockHeadersReportsStrategyTimeoutWhenANodeHitsTheSameDeadline checks that a node returning the strategy's
// own deadline as its error is still reported as the strategy timeout, whichever arrives first.  It uses the real clock
// with a short timeout and many runs, because the fake clock always delivers the strategy's deadline first.
func TestBeaconBlockHeadersReportsStrategyTimeoutWhenANodeHitsTheSameDeadline(t *testing.T) {
	for range 500 {
		func() {
			s, err := first.New(context.Background(),
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(time.Millisecond),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"waiting": &deadlineProvider{},
				}),
			)
			require.NoError(t, err)

			_, err = s.BeaconBlockHeader(context.Background(), &api.BeaconBlockHeaderOpts{Block: "1"})
			require.ErrorIs(t, err, first.ErrBeaconBlockHeaderTimeout)
		}()
	}
}

// TestBeaconBlockHeadersReportsStrategyTimeoutWhenAnAbstentionHitsTheDeadline checks that a node which abstains only
// because the strategy's deadline cut off its health check does not let another node's 404 decide.
func TestBeaconBlockHeadersReportsStrategyTimeoutWhenAnAbstentionHitsTheDeadline(t *testing.T) {
	for range 500 {
		s, err := first.New(context.Background(),
			first.WithLogLevel(zerolog.Disabled),
			first.WithTimeout(time.Millisecond),
			first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
				"missing":  &headerErrorProvider{err: &api.Error{StatusCode: 404}},
				"checking": &deadlineProvider{err: consensusclient.ErrNotActive},
			}),
		)
		require.NoError(t, err)

		_, err = s.BeaconBlockHeader(context.Background(), &api.BeaconBlockHeaderOpts{Block: "1"})
		require.ErrorIs(t, err, first.ErrBeaconBlockHeaderTimeout)
		require.False(t, util.IsNotFound(err))
	}
}

// deadlineProvider answers only when the caller's context ends, with err or else that context's error.
type deadlineProvider struct {
	err error
}

func (p *deadlineProvider) BeaconBlockHeader(ctx context.Context, _ *api.BeaconBlockHeaderOpts) (*api.Response[*apiv1.BeaconBlockHeader], error) {
	<-ctx.Done()
	if p.err != nil {
		return nil, p.err
	}

	return nil, ctx.Err()
}

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

// connectionRefused returns the error a request to a closed port gives, wrapped as go-eth2-client wraps it.
func connectionRefused(t *testing.T) error {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	resp, err := http.Get("http://" + address + "/eth/v1/beacon/headers/1")
	if resp != nil {
		require.NoError(t, resp.Body.Close())
	}
	require.Error(t, err)

	return errors.Join(errors.New("failed to call GET endpoint"), err)
}

type headerErrorProvider struct {
	err error
}

func (p *headerErrorProvider) BeaconBlockHeader(context.Context, *api.BeaconBlockHeaderOpts) (*api.Response[*apiv1.BeaconBlockHeader], error) {
	return nil, p.err
}

func TestBeaconBlockHeaders(t *testing.T) {
	refused := connectionRefused(t)
	dialTimeout := errors.Join(errors.New("failed to call GET endpoint"),
		&url.Error{Op: "Get", URL: "http://slow:5052", Err: &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}})
	notFound := &api.Error{StatusCode: 404}
	serviceUnavailable := &api.Error{StatusCode: 503}
	errProviderFailure := errors.New("unexpected provider failure")
	tests := []struct {
		name            string
		params          []first.Parameter
		blockID         string
		beaconBlockRoot phase0.Root
		err             string
		errIs           error
		errIsNot        []error
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
			blockID: "1",
			// The node's own deadline fired, not the strategy's, so report it as that node's error.
			errIs:       context.DeadlineExceeded,
			errIsNot:    []error{notFound, first.ErrBeaconBlockHeaderTimeout},
			errContains: "timed-out",
			answered:    true,
		},
		{
			name: "NotFoundAndFound",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"missing": &headerErrorProvider{err: notFound},
					"good":    mock.NewBeaconBlockHeadersProvider(),
				}),
			},
			blockID:  "1",
			answered: true,
		},
		{
			name: "NotFoundAndConnectionRefused",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"missing": &headerErrorProvider{err: notFound},
					"down":    &headerErrorProvider{err: refused},
				}),
			},
			blockID:  "1",
			errIs:    notFound,
			answered: true,
		},
		{
			name: "AllConnectionRefused",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"down1": &headerErrorProvider{err: refused},
					"down2": &headerErrorProvider{err: refused},
				}),
			},
			blockID:     "1",
			errIs:       syscall.ECONNREFUSED,
			errIsNot:    []error{notFound},
			errContains: "down1",
			answered:    true,
		},
		{
			name: "AllNotActive",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"down1": &headerErrorProvider{err: consensusclient.ErrNotActive},
					"down2": &headerErrorProvider{err: consensusclient.ErrNotActive},
				}),
			},
			blockID:  "1",
			errIs:    consensusclient.ErrNotActive,
			errIsNot: []error{notFound},
			answered: true,
		},
		{
			name: "NotFoundAndDialTimeout",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"missing": &headerErrorProvider{err: notFound},
					"slow":    &headerErrorProvider{err: dialTimeout},
				}),
			},
			blockID:     "1",
			errIs:       context.DeadlineExceeded,
			errIsNot:    []error{notFound},
			errContains: "slow",
			answered:    true,
		},
		{
			name: "ProviderFailureThenStrategyTimeout",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"offline": &headerErrorProvider{err: errProviderFailure},
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
			errIsNot: []error{notFound},
		},
		{
			name: "ProviderFailure",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"offline": &headerErrorProvider{err: errProviderFailure},
				}),
			},
			blockID:  "1",
			errIs:    errProviderFailure,
			answered: true,
		},
		{
			name: "NotFoundAndProviderFailure",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{
					"missing": &headerErrorProvider{err: notFound},
					"offline": &headerErrorProvider{err: errProviderFailure},
				}),
			},
			blockID:  "1",
			errIs:    errProviderFailure,
			errIsNot: []error{notFound},
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
			errIsNot: []error{notFound},
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
			for _, unexpected := range test.errIsNot {
				require.NotErrorIs(t, err, unexpected)
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
