// Copyright © 2022 Attestant Limited.
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
	mockattestationaggregator "github.com/attestantio/vouch/services/attestationaggregator/mock"
	"github.com/attestantio/vouch/services/beaconcommitteesubscriber/standard"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
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

	attesterDutiesProvider := mock.NewAttesterDutiesProvider()
	beaconCommitteesSubmitter := mock.NewBeaconCommitteeSubscriptionsSubmitter()
	attestationAggregator := mockattestationaggregator.New()

	tests := []struct {
		name     string
		params   []standard.Parameter
		err      string
		logEntry string
	}{
		{
			name: "ProcessConcurrencyZero",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(0),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithBeaconCommitteeSubmitter(beaconCommitteesSubmitter),
				standard.WithAttestationAggregator(attestationAggregator),
			},
			err: "problem with parameters: no process concurrency specified",
		},
		{
			name: "MonitorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(2),
				standard.WithMonitor(nil),
				standard.WithChainTimeService(chainTime),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithBeaconCommitteeSubmitter(beaconCommitteesSubmitter),
				standard.WithAttestationAggregator(attestationAggregator),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ChainTimeServiceMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(2),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithBeaconCommitteeSubmitter(beaconCommitteesSubmitter),
				standard.WithAttestationAggregator(attestationAggregator),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "AttesterDutiesProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(2),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithBeaconCommitteeSubmitter(beaconCommitteesSubmitter),
				standard.WithAttestationAggregator(attestationAggregator),
			},
			err: "problem with parameters: no attester duties provider specified",
		},
		{
			name: "BeaconCommitteeSubmitterMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(2),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithAttestationAggregator(attestationAggregator),
			},
			err: "problem with parameters: no beacon committee submitter specified",
		},
		{
			name: "AttestationAggregatorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(2),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithBeaconCommitteeSubmitter(beaconCommitteesSubmitter),
			},
			err: "problem with parameters: no attestation aggregator specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(2),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithBeaconCommitteeSubmitter(beaconCommitteesSubmitter),
				standard.WithAttestationAggregator(attestationAggregator),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := standard.New(ctx, test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
