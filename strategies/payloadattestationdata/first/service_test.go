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

package first_test

import (
	"context"
	"sync"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	mockclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/strategies/payloadattestationdata/first"
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

func payloadAttestationDataProvider(t *testing.T, fn func(context.Context, *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error)) eth2client.PayloadAttestationDataProvider {
	t.Helper()
	provider, err := mockclient.New(context.Background())
	require.NoError(t, err)
	provider.PayloadAttestationDataFunc = fn
	return provider
}

func validData(slot phase0.Slot) *api.Response[*spec.VersionedPayloadAttestationData] {
	return &api.Response[*spec.VersionedPayloadAttestationData]{
		Data: &spec.VersionedPayloadAttestationData{
			Version: spec.DataVersionGloas,
			Gloas: &gloas.PayloadAttestationData{
				Slot:           slot,
				PayloadPresent: true,
			},
		},
	}
}

func TestPayloadAttestationData(t *testing.T) {
	ctx := context.Background()
	monitor := &monitor{}
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(monitor),
		first.WithPayloadAttestationDataProviders(map[string]eth2client.PayloadAttestationDataProvider{
			"invalid": payloadAttestationDataProvider(t, func(context.Context, *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
				return &api.Response[*spec.VersionedPayloadAttestationData]{}, nil
			}),
			"valid": payloadAttestationDataProvider(t, func(_ context.Context, opts *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
				time.Sleep(10 * time.Millisecond)
				return validData(opts.Slot), nil
			}),
		}),
	)
	require.NoError(t, err)

	response, err := service.PayloadAttestationData(ctx, &api.PayloadAttestationDataOpts{Slot: 12})
	require.NoError(t, err)
	require.Equal(t, validData(12).Data, response.Data)
	require.ElementsMatch(t, []string{"invalid", "valid"}, monitor.clients)
	require.Equal(t, []string{"valid"}, monitor.strategy)
}

func TestPayloadAttestationDataHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service, err := first.New(ctx,
		first.WithPayloadAttestationDataProviders(map[string]eth2client.PayloadAttestationDataProvider{
			"slow": payloadAttestationDataProvider(t, func(ctx context.Context, _ *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}),
		}),
	)
	require.NoError(t, err)
	_, err = service.PayloadAttestationData(ctx, &api.PayloadAttestationDataOpts{Slot: 12})
	require.ErrorIs(t, err, context.Canceled)
}
