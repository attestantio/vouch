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

package majority_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	mockclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/strategies/payloadattestationdata/majority"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type monitor struct {
	mu       sync.Mutex
	clients  []string
	strategy []string
}

func (m *monitor) ClientOperation(provider string, _ string, _ bool, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients = append(m.clients, provider)
}

func (m *monitor) StrategyOperation(_ string, provider string, _ string, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.strategy = append(m.strategy, provider)
}

func provider(t *testing.T, response *api.Response[*spec.VersionedPayloadAttestationData]) eth2client.PayloadAttestationDataProvider {
	t.Helper()
	provider, err := mockclient.New(context.Background())
	require.NoError(t, err)
	provider.PayloadAttestationDataFunc = func(context.Context, *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
		return response, nil
	}
	return provider
}

func data(slot phase0.Slot, root phase0.Root, payloadPresent, blobDataAvailable bool) *api.Response[*spec.VersionedPayloadAttestationData] {
	return &api.Response[*spec.VersionedPayloadAttestationData]{
		Data: &spec.VersionedPayloadAttestationData{
			Version: spec.DataVersionGloas,
			Gloas: &gloas.PayloadAttestationData{
				Slot:              slot,
				BeaconBlockRoot:   root,
				PayloadPresent:    payloadPresent,
				BlobDataAvailable: blobDataAvailable,
			},
		},
	}
}

func erroringProvider(t *testing.T, err error) eth2client.PayloadAttestationDataProvider {
	t.Helper()
	provider, newErr := mockclient.New(context.Background())
	require.NoError(t, newErr)
	provider.PayloadAttestationDataFunc = func(context.Context, *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
		return nil, err
	}
	return provider
}

func TestPayloadAttestationDataAgreement(t *testing.T) {
	ctx := context.Background()
	response := data(12, phase0.Root{1}, true, true)
	monitor := &monitor{}
	service, err := majority.New(ctx,
		majority.WithLogLevel(zerolog.Disabled),
		majority.WithClientMonitor(monitor),
		majority.WithTimeout(time.Second),
		majority.WithThreshold(2),
		majority.WithPayloadAttestationDataProviders(map[string]eth2client.PayloadAttestationDataProvider{
			"one": provider(t, response),
			"two": provider(t, response),
		}),
	)
	require.NoError(t, err)

	actual, err := service.PayloadAttestationData(ctx, &api.PayloadAttestationDataOpts{Slot: 12})
	require.NoError(t, err)
	require.Equal(t, response.Data, actual.Data)
	require.Empty(t, actual.Metadata)
	require.ElementsMatch(t, []string{"one", "two"}, monitor.clients)
	require.ElementsMatch(t, []string{"one", "two"}, monitor.strategy)
}

func delayedProvider(t *testing.T, response *api.Response[*spec.VersionedPayloadAttestationData], delay time.Duration) eth2client.PayloadAttestationDataProvider {
	t.Helper()
	provider, err := mockclient.New(context.Background())
	require.NoError(t, err)
	provider.PayloadAttestationDataFunc = func(ctx context.Context, _ *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
		select {
		case <-time.After(delay):
			return response, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return provider
}

func TestPayloadAttestationDataThresholdExceedingStrictMajority(t *testing.T) {
	ctx := context.Background()
	root := phase0.Root{1}
	response := data(12, root, true, true)
	service, err := majority.New(ctx,
		majority.WithTimeout(time.Second),
		majority.WithThreshold(4),
		majority.WithPayloadAttestationDataProviders(map[string]eth2client.PayloadAttestationDataProvider{
			"one":   provider(t, response),
			"two":   provider(t, response),
			"three": provider(t, response),
			"four":  delayedProvider(t, response, 10*time.Millisecond),
			"other": provider(t, data(12, phase0.Root{2}, true, true)),
		}),
	)
	require.NoError(t, err)
	actual, err := service.PayloadAttestationData(ctx, &api.PayloadAttestationDataOpts{Slot: 12})
	require.NoError(t, err)
	require.Equal(t, response.Data, actual.Data)
}

func TestPayloadAttestationDataUsesResponsesReceivedAtTimeout(t *testing.T) {
	ctx := context.Background()
	root := phase0.Root{1}
	response := data(12, root, true, true)
	service, err := majority.New(ctx,
		majority.WithLogLevel(zerolog.Disabled),
		majority.WithTimeout(100*time.Millisecond),
		majority.WithPayloadAttestationDataProviders(map[string]eth2client.PayloadAttestationDataProvider{
			"one":   provider(t, response),
			"two":   provider(t, response),
			"three": provider(t, data(12, phase0.Root{2}, true, true)),
			// A strict majority of 3 is never reached, so the strategy waits for this
			// provider until the timeout and must then use the responses it has.
			"hung": delayedProvider(t, response, time.Minute),
		}),
	)
	require.NoError(t, err)

	actual, err := service.PayloadAttestationData(ctx, &api.PayloadAttestationDataOpts{Slot: 12})
	require.NoError(t, err)
	require.Equal(t, response.Data, actual.Data)
}

func TestPayloadAttestationDataSelection(t *testing.T) {
	ctx := context.Background()
	root1 := phase0.Root{1}
	root2 := phase0.Root{2}
	tests := []struct {
		name      string
		providers map[string]eth2client.PayloadAttestationDataProvider
		threshold int
		expected  *spec.VersionedPayloadAttestationData
		err       string
	}{
		{
			name: "UniquePlurality",
			providers: map[string]eth2client.PayloadAttestationDataProvider{
				"one":   provider(t, data(12, root1, true, true)),
				"two":   provider(t, data(12, root1, true, true)),
				"three": provider(t, data(12, root2, true, true)),
				"four":  provider(t, data(12, phase0.Root{3}, true, true)),
			},
			threshold: 2,
			expected:  data(12, root1, true, true).Data,
		},
		{
			name: "ThresholdFailure",
			providers: map[string]eth2client.PayloadAttestationDataProvider{
				"one": provider(t, data(12, root1, true, true)),
				"two": provider(t, data(12, root1, true, true)),
			},
			threshold: 3,
			err:       "payload attestation data count of 2 lower than threshold 3",
		},
		{
			name: "ThresholdZero",
			providers: map[string]eth2client.PayloadAttestationDataProvider{
				"one": provider(t, data(12, root1, true, true)),
			},
			expected: data(12, root1, true, true).Data,
		},
		{
			name: "NoValidResponse",
			providers: map[string]eth2client.PayloadAttestationDataProvider{
				"invalid": provider(t, &api.Response[*spec.VersionedPayloadAttestationData]{}),
			},
			err: "no valid payload attestation data received",
		},
		{
			name: "InvalidResponseDoesNotVote",
			providers: map[string]eth2client.PayloadAttestationDataProvider{
				"invalid": provider(t, &api.Response[*spec.VersionedPayloadAttestationData]{}),
				"valid":   provider(t, data(12, root1, true, true)),
			},
			threshold: 1,
			expected:  data(12, root1, true, true).Data,
		},
		{
			name: "ProviderFailureDoesNotVote",
			providers: map[string]eth2client.PayloadAttestationDataProvider{
				"error": erroringProvider(t, errors.New("failed")),
				"valid": provider(t, data(12, root1, true, true)),
			},
			threshold: 1,
			expected:  data(12, root1, true, true).Data,
		},
		{
			name: "SameRootPayloadPresenceTie",
			providers: map[string]eth2client.PayloadAttestationDataProvider{
				"absent":  provider(t, data(12, root1, false, true)),
				"present": provider(t, data(12, root1, true, true)),
			},
			threshold: 1,
			expected:  data(12, root1, true, true).Data,
		},
		{
			name: "BlobOnlyTieFails",
			providers: map[string]eth2client.PayloadAttestationDataProvider{
				"unavailable": provider(t, data(12, root1, false, false)),
				"available":   provider(t, data(12, root1, false, true)),
			},
			threshold: 1,
			err:       "split-response payload attestation data responses",
		},
		{
			name: "CompetingRootsFail",
			providers: map[string]eth2client.PayloadAttestationDataProvider{
				"one": provider(t, data(12, root1, true, true)),
				"two": provider(t, data(12, root2, true, true)),
			},
			threshold: 1,
			err:       "split-root payload attestation data responses",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := majority.New(ctx,
				majority.WithLogLevel(zerolog.Disabled),
				majority.WithTimeout(time.Second),
				majority.WithThreshold(test.threshold),
				majority.WithPayloadAttestationDataProviders(test.providers),
			)
			require.NoError(t, err)
			actual, err := service.PayloadAttestationData(ctx, &api.PayloadAttestationDataOpts{Slot: 12})
			if test.err != "" {
				require.EqualError(t, err, test.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, actual.Data)
		})
	}
}

func TestPayloadAttestationDataHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service, err := majority.New(ctx,
		majority.WithTimeout(time.Second),
		majority.WithPayloadAttestationDataProviders(map[string]eth2client.PayloadAttestationDataProvider{
			"slow": erroringProvider(t, context.Canceled),
		}),
	)
	require.NoError(t, err)
	_, err = service.PayloadAttestationData(ctx, &api.PayloadAttestationDataOpts{Slot: 12})
	require.ErrorIs(t, err, context.Canceled)
}
