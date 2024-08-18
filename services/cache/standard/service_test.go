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

package standard_test

import (
	"context"
	"testing"
	"time"

	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/cache/standard"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mockscheduler "github.com/attestantio/vouch/services/scheduler/mock"
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

	monitor := nullmetrics.New()
	signedBeaconBlockProvider := mock.NewSignedBeaconBlockProvider()
	beaconBlockHeadersProvider := mock.NewBeaconBlockHeadersProvider()
	eventsProvider := mock.NewEventsProvider()
	scheduler := mockscheduler.New()

	tests := []struct {
		name   string
		params []standard.Parameter
		err    string
	}{
		{
			name: "MonitorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nil),
				standard.WithChainTime(chainTime),
				standard.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
				standard.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
				standard.WithEventsProvider(eventsProvider),
				standard.WithScheduler(scheduler),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ChainTimeMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
				standard.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
				standard.WithEventsProvider(eventsProvider),
				standard.WithScheduler(scheduler),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "SignedBeaconBlockProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithChainTime(chainTime),
				standard.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
				standard.WithEventsProvider(eventsProvider),
				standard.WithScheduler(scheduler),
			},
			err: "problem with parameters: no signed beacon block provider specified",
		},
		{
			name: "BeaconBlockHeadersProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithChainTime(chainTime),
				standard.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
				standard.WithEventsProvider(eventsProvider),
				standard.WithScheduler(scheduler),
			},
			err: "problem with parameters: no beacon block headers provider specified",
		},
		{
			name: "EventsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithChainTime(chainTime),
				standard.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
				standard.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
				standard.WithScheduler(scheduler),
			},
			err: "problem with parameters: no events provider specified",
		},
		{
			name: "SchedulerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithChainTime(chainTime),
				standard.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
				standard.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
				standard.WithEventsProvider(eventsProvider),
			},
			err: "problem with parameters: no scheduler specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithChainTime(chainTime),
				standard.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
				standard.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
				standard.WithEventsProvider(eventsProvider),
				standard.WithScheduler(scheduler),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := standard.New(context.Background(), test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
