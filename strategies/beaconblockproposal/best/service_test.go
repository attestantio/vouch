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

package best_test

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
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/strategies/beaconblockproposal/best"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	blockToSlotCache := cacheSvc.(cache.BlockRootToSlotProvider)

	tests := []struct {
		name   string
		params []best.Parameter
		err    string
	}{
		{
			name: "ClientMonitorMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithClientMonitor(nil),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(1),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"one":   mock.NewProposalProvider(),
					"two":   mock.NewProposalProvider(),
					"three": mock.NewProposalProvider(),
				}),
				best.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "TimeoutMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(1),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"one":   mock.NewProposalProvider(),
					"two":   mock.NewProposalProvider(),
					"three": mock.NewProposalProvider(),
				}),
				best.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "TimeoutZero",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithTimeout(0),
				best.WithProcessConcurrency(1),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"one":   mock.NewProposalProvider(),
					"two":   mock.NewProposalProvider(),
					"three": mock.NewProposalProvider(),
				}),
				best.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "EventsProviderMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(1),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"one":   mock.NewProposalProvider(),
					"two":   mock.NewProposalProvider(),
					"three": mock.NewProposalProvider(),
				}),
				best.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no events provider specified",
		},
		{
			name: "ChainTimeServiceMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(1),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"one":   mock.NewProposalProvider(),
					"two":   mock.NewProposalProvider(),
					"three": mock.NewProposalProvider(),
				}),
				best.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "SpecProviderMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithProcessConcurrency(1),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"one":   mock.NewProposalProvider(),
					"two":   mock.NewProposalProvider(),
					"three": mock.NewProposalProvider(),
				}),
				best.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no spec provider specified",
		},
		{
			name: "ProcessConcurrencyBad",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(0),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"one":   mock.NewProposalProvider(),
					"two":   mock.NewProposalProvider(),
					"three": mock.NewProposalProvider(),
				}),
				best.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no process concurrency specified",
		},
		{
			name: "ProposalProvidersMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(1),
				best.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no proposal providers specified",
		},
		{
			name: "ProposalProvidersEmpty",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(1),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{}),
				best.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no proposal providers specified",
		},
		{
			name: "SignedBeaconBlockProviderMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(1),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"one":   mock.NewProposalProvider(),
					"two":   mock.NewProposalProvider(),
					"three": mock.NewProposalProvider(),
				}),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "problem with parameters: no signed beacon block provider specified",
		},
		{
			name: "ErroringSpecProvider",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(mock.NewErroringSpecProvider()),
				best.WithProcessConcurrency(1),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"one":   mock.NewProposalProvider(),
					"two":   mock.NewProposalProvider(),
					"three": mock.NewProposalProvider(),
				}),
				best.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "failed to obtain spec: error",
		},
		{
			name: "ErroringEventsProvider",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithEventsProvider(mock.NewErroringEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(1),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"one":   mock.NewProposalProvider(),
					"two":   mock.NewProposalProvider(),
					"three": mock.NewProposalProvider(),
				}),
				best.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			err: "failed to add head event handler: error",
		},
		{
			name: "Good",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(1),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"one":   mock.NewProposalProvider(),
					"two":   mock.NewProposalProvider(),
					"three": mock.NewProposalProvider(),
				}),
				best.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := best.New(context.Background(), test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
