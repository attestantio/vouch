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

package majority_test

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
	"github.com/attestantio/vouch/strategies/attestationdata/majority"
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
		params []majority.Parameter
		err    string
	}{
		{
			name: "TimeoutMissing",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithAttestationDataProviders(attestationDataProviders),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "TimeoutZero",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(0),
				majority.WithAttestationDataProviders(attestationDataProviders),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "ClientMonitorMissing",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(2 * time.Second),
				majority.WithClientMonitor(nil),
				majority.WithAttestationDataProviders(attestationDataProviders),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "AttestationDataProvidersNil",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(2 * time.Second),
				majority.WithAttestationDataProviders(nil),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
			err: "problem with parameters: no attestation data providers specified",
		},
		{
			name: "AttestationDataProvidersEmpty",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(2 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
			err: "problem with parameters: no attestation data providers specified",
		},
		{
			name: "ChainTimeMissing",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(2 * time.Second),
				majority.WithAttestationDataProviders(attestationDataProviders),
				majority.WithBlockRootToSlotCache(cache),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "Good",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(2 * time.Second),
				majority.WithAttestationDataProviders(attestationDataProviders),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
		},
		{
			name: "BlockRootToSlotCacheMissing",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(2 * time.Second),
				majority.WithAttestationDataProviders(attestationDataProviders),
				majority.WithChainTime(chainTime),
			},
			err: "problem with parameters: no block root to slot cache specified",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := majority.New(context.Background(), test.params...)
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

	s, err := majority.New(context.Background(),
		majority.WithLogLevel(zerolog.Disabled),
		majority.WithTimeout(2*time.Second),
		majority.WithAttestationDataProviders(attestationDataProviders),
		majority.WithChainTime(chainTime),
		majority.WithBlockRootToSlotCache(cache),
	)
	require.NoError(t, err)
	require.Implements(t, (*eth2client.AttestationDataProvider)(nil), s)
}
