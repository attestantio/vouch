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

package staticdelay_test

import (
	"context"
	"testing"
	"time"

	"github.com/attestantio/vouch/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/multiinstance/staticdelay"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	ctx := context.Background()

	zerolog.SetGlobalLevel(zerolog.Disabled)

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	beaconBlockHeadersProvider := mock.NewBeaconBlockHeadersProvider()
	attestationPoolProvider := mock.NewAttestationPoolProvider()

	monitor := nullmetrics.New()

	tests := []struct {
		name     string
		params   []staticdelay.Parameter
		err      string
		logEntry string
	}{
		{
			name: "MonitorMissing",
			params: []staticdelay.Parameter{
				staticdelay.WithLogLevel(zerolog.Disabled),
				staticdelay.WithMonitor(nil),
				staticdelay.WithAttestationPoolProvider(attestationPoolProvider),
				staticdelay.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
				staticdelay.WithChainTime(chainTime),
				staticdelay.WithAttesterDelay(100 * time.Millisecond),
				staticdelay.WithProposerDelay(100 * time.Millisecond),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "AttestationProviderMissing",
			params: []staticdelay.Parameter{
				staticdelay.WithLogLevel(zerolog.Disabled),
				staticdelay.WithMonitor(monitor),
				staticdelay.WithAttestationPoolProvider(nil),
				staticdelay.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
				staticdelay.WithChainTime(chainTime),
				staticdelay.WithAttesterDelay(100 * time.Millisecond),
				staticdelay.WithProposerDelay(100 * time.Millisecond),
			},
			err: "problem with parameters: no attestation pool provider specified",
		},
		{
			name: "BeaconBlockHeadersProviderMissing",
			params: []staticdelay.Parameter{
				staticdelay.WithLogLevel(zerolog.Disabled),
				staticdelay.WithMonitor(monitor),
				staticdelay.WithAttestationPoolProvider(attestationPoolProvider),
				staticdelay.WithBeaconBlockHeadersProvider(nil),
				staticdelay.WithChainTime(chainTime),
				staticdelay.WithAttesterDelay(100 * time.Millisecond),
				staticdelay.WithProposerDelay(100 * time.Millisecond),
			},
			err: "problem with parameters: no beacon block headers provider specified",
		},
		{
			name: "ChainTimeMissing",
			params: []staticdelay.Parameter{
				staticdelay.WithLogLevel(zerolog.Disabled),
				staticdelay.WithMonitor(monitor),
				staticdelay.WithAttestationPoolProvider(attestationPoolProvider),
				staticdelay.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
				staticdelay.WithChainTime(nil),
				staticdelay.WithAttesterDelay(100 * time.Millisecond),
				staticdelay.WithProposerDelay(100 * time.Millisecond),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "AttesterDelayNegative",
			params: []staticdelay.Parameter{
				staticdelay.WithLogLevel(zerolog.Disabled),
				staticdelay.WithMonitor(monitor),
				staticdelay.WithAttestationPoolProvider(attestationPoolProvider),
				staticdelay.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
				staticdelay.WithChainTime(chainTime),
				staticdelay.WithAttesterDelay(-1),
				staticdelay.WithProposerDelay(100 * time.Millisecond),
			},
			err: "problem with parameters: attester delay cannot be negative",
		},
		{
			name: "ProposerDelayNegative",
			params: []staticdelay.Parameter{
				staticdelay.WithLogLevel(zerolog.Disabled),
				staticdelay.WithMonitor(monitor),
				staticdelay.WithAttestationPoolProvider(attestationPoolProvider),
				staticdelay.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
				staticdelay.WithChainTime(chainTime),
				staticdelay.WithAttesterDelay(100 * time.Millisecond),
				staticdelay.WithProposerDelay(-1),
			},
			err: "problem with parameters: proposer delay cannot be negative",
		},
		{
			name: "Good",
			params: []staticdelay.Parameter{
				staticdelay.WithLogLevel(zerolog.Disabled),
				staticdelay.WithMonitor(monitor),
				staticdelay.WithAttestationPoolProvider(attestationPoolProvider),
				staticdelay.WithBeaconBlockHeadersProvider(beaconBlockHeadersProvider),
				staticdelay.WithChainTime(chainTime),
				staticdelay.WithAttesterDelay(100 * time.Millisecond),
				staticdelay.WithProposerDelay(100 * time.Millisecond),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			_, err := staticdelay.New(ctx, test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				if test.logEntry != "" {
					capture.AssertHasEntry(t, test.logEntry)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
