// Copyright © 2020 Attestant Limited.
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

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/strategies/beaconblockproposal/best"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	tests := []struct {
		name   string
		params []best.Parameter
		err    string
	}{
		{
			name: "ClientMonitorMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithClientMonitor(nil),
				best.WithProcessConcurrency(1),
				best.WithBeaconBlockProposalProviders(map[string]eth2client.BeaconBlockProposalProvider{
					"one":   mock.NewBeaconBlockProposalProvider(),
					"two":   mock.NewBeaconBlockProposalProvider(),
					"three": mock.NewBeaconBlockProposalProvider(),
				}),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "TimeoutMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithClientMonitor(null.New(context.Background())),
				best.WithTimeout(0),
				best.WithProcessConcurrency(1),
				best.WithBeaconBlockProposalProviders(map[string]eth2client.BeaconBlockProposalProvider{
					"one":   mock.NewBeaconBlockProposalProvider(),
					"two":   mock.NewBeaconBlockProposalProvider(),
					"three": mock.NewBeaconBlockProposalProvider(),
				}),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "ProcessConcurrencyBad",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithClientMonitor(null.New(context.Background())),
				best.WithProcessConcurrency(0),
				best.WithBeaconBlockProposalProviders(map[string]eth2client.BeaconBlockProposalProvider{
					"one":   mock.NewBeaconBlockProposalProvider(),
					"two":   mock.NewBeaconBlockProposalProvider(),
					"three": mock.NewBeaconBlockProposalProvider(),
				}),
			},
			err: "problem with parameters: no process concurrency specified",
		},
		{
			name: "ProvidersMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithClientMonitor(null.New(context.Background())),
				best.WithProcessConcurrency(1),
			},
			err: "problem with parameters: no beacon block proposal providers specified",
		},
		{
			name: "ProvidersEmpty",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithClientMonitor(null.New(context.Background())),
				best.WithProcessConcurrency(1),
				best.WithBeaconBlockProposalProviders(map[string]eth2client.BeaconBlockProposalProvider{}),
			},
			err: "problem with parameters: no beacon block proposal providers specified",
		},
		{
			name: "Good",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithClientMonitor(null.New(context.Background())),
				best.WithProcessConcurrency(1),
				best.WithBeaconBlockProposalProviders(map[string]eth2client.BeaconBlockProposalProvider{
					"one":   mock.NewBeaconBlockProposalProvider(),
					"two":   mock.NewBeaconBlockProposalProvider(),
					"three": mock.NewBeaconBlockProposalProvider(),
				}),
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
