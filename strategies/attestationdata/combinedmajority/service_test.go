// Copyright © 2025 Attestant Limited.
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

package combinedmajority_test

import (
	"context"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/attestantio/vouch/strategies/attestationdata/combinedmajority"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	ctx := context.Background()

	attestationDataProviders := map[string]eth2client.AttestationDataProvider{
		"localhost:1": mock.NewAttestationDataProvider(),
	}

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	cache := mockcache.New(map[phase0.Root]phase0.Slot{}).(cache.BlockRootToSlotProvider)

	tests := []struct {
		name   string
		params []combinedmajority.Parameter
		err    string
	}{
		{
			name: "TimeoutMissing",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithAttestationDataProviders(attestationDataProviders),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(cache),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "TimeoutZero",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(0),
				combinedmajority.WithAttestationDataProviders(attestationDataProviders),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(cache),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "ClientMonitorMissing",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(2 * time.Second),
				combinedmajority.WithClientMonitor(nil),
				combinedmajority.WithAttestationDataProviders(attestationDataProviders),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(cache),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "AttestationDataProvidersNil",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(2 * time.Second),
				combinedmajority.WithAttestationDataProviders(nil),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(cache),
			},
			err: "problem with parameters: no attestation data providers specified",
		},
		{
			name: "AttestationDataProvidersEmpty",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(2 * time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(cache),
			},
			err: "problem with parameters: no attestation data providers specified",
		},
		{
			name: "ChainTimeMissing",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(2 * time.Second),
				combinedmajority.WithAttestationDataProviders(attestationDataProviders),
				combinedmajority.WithBlockRootToSlotCache(cache),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "Good",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(2 * time.Second),
				combinedmajority.WithAttestationDataProviders(attestationDataProviders),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(cache),
			},
		},
		{
			name: "BlockRootToSlotCacheMissing",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(2 * time.Second),
				combinedmajority.WithAttestationDataProviders(attestationDataProviders),
				combinedmajority.WithChainTime(chainTime),
			},
			err: "problem with parameters: no block root to slot cache specified",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := combinedmajority.New(context.Background(), test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestInterfaces(t *testing.T) {
	ctx := context.Background()

	attestationDataProviders := map[string]eth2client.AttestationDataProvider{
		"localhost:1": mock.NewAttestationDataProvider(),
	}

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	cache := mockcache.New(map[phase0.Root]phase0.Slot{}).(cache.BlockRootToSlotProvider)

	s, err := combinedmajority.New(context.Background(),
		combinedmajority.WithLogLevel(zerolog.Disabled),
		combinedmajority.WithTimeout(2*time.Second),
		combinedmajority.WithAttestationDataProviders(attestationDataProviders),
		combinedmajority.WithChainTime(chainTime),
		combinedmajority.WithBlockRootToSlotCache(cache),
	)
	require.NoError(t, err)
	require.Implements(t, (*eth2client.AttestationDataProvider)(nil), s)
}
