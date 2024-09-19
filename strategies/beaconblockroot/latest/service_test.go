// Copyright © 2024 Attestant Limited.
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

package latest_test

import (
	"context"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	"github.com/attestantio/vouch/strategies/beaconblockroot/latest"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	beaconBlockRootProviders := map[string]eth2client.BeaconBlockRootProvider{
		"localhost:1": mock.NewBeaconBlockRootProvider(),
	}

	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	blockToSlotCache := cacheSvc.(cache.BlockRootToSlotProvider)

	tests := []struct {
		name   string
		params []latest.Parameter
		err    string
	}{
		{
			name: "TimeoutMissing",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.Disabled),
				latest.WithBeaconBlockRootProviders(beaconBlockRootProviders),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "TimeoutZero",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.Disabled),
				latest.WithTimeout(0),
				latest.WithBeaconBlockRootProviders(beaconBlockRootProviders),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "ClientMonitorMissing",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.Disabled),
				latest.WithTimeout(2 * time.Second),
				latest.WithClientMonitor(nil),
				latest.WithBeaconBlockRootProviders(beaconBlockRootProviders),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "BeaconBlockRootProvidersNil",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.Disabled),
				latest.WithTimeout(2 * time.Second),
				latest.WithBeaconBlockRootProviders(nil),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no beacon block root providers specified",
		},
		{
			name: "ProcessConcurrencyZero",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.Disabled),
				latest.WithTimeout(2 * time.Second),
				latest.WithBeaconBlockRootProviders(beaconBlockRootProviders),
				latest.WithProcessConcurrency(0),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no process concurrency specified",
		},
		{
			name: "BeaconBlockRootProvidersEmpty",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.Disabled),
				latest.WithTimeout(2 * time.Second),
				latest.WithBeaconBlockRootProviders(map[string]eth2client.BeaconBlockRootProvider{}),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no beacon block root providers specified",
		},
		{
			name: "BlockRootToSlotCacheMissing",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.Disabled),
				latest.WithTimeout(2 * time.Second),
				latest.WithBeaconBlockRootProviders(beaconBlockRootProviders),
			},
			err: "problem with parameters: no block root to slot cache specified",
		},
		{
			name: "Good",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.Disabled),
				latest.WithTimeout(2 * time.Second),
				latest.WithBeaconBlockRootProviders(beaconBlockRootProviders),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := latest.New(context.Background(), test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestInterfaces(t *testing.T) {
	beaconBlockRootProviders := map[string]eth2client.BeaconBlockRootProvider{
		"localhost:1": mock.NewBeaconBlockRootProvider(),
	}

	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	blockToSlotCache := cacheSvc.(cache.BlockRootToSlotProvider)

	s, err := latest.New(context.Background(),
		latest.WithLogLevel(zerolog.Disabled),
		latest.WithTimeout(2*time.Second),
		latest.WithBeaconBlockRootProviders(beaconBlockRootProviders),
		latest.WithBlockRootToSlotCache(blockToSlotCache),
	)
	require.NoError(t, err)
	require.Implements(t, (*eth2client.BeaconBlockRootProvider)(nil), s)
}
