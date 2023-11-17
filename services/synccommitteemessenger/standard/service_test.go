// Copyright © 2021 Attestant Limited.
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

	mocketh2client "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	nullsubmitter "github.com/attestantio/vouch/services/submitter/null"
	mocksynccommitteeaggregator "github.com/attestantio/vouch/services/synccommitteeaggregator/mock"
	"github.com/attestantio/vouch/services/synccommitteemessenger/standard"
	"github.com/attestantio/vouch/testing/logger"
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

	mockSyncCommitteeAggregator := mocksynccommitteeaggregator.New()
	mockSigner := mocksigner.New()
	nullSubmitter, err := nullsubmitter.New(ctx)
	require.NoError(t, err)
	mockETH2Client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	mockValidatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()

	tests := []struct {
		name     string
		params   []standard.Parameter
		err      string
		logEntry string
	}{
		{
			name: "ProcessConcurrencyBad",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(-1),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no process concurrency specified",
		},
		{
			name: "MonitorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nil),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ChainTimeMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "SyncCommitteeAggregatorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithChainTimeService(chainTime),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no sync committee aggregator specified",
		},
		{
			name: "SpecProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no spec provider specified",
		},
		{
			name: "BeaconBlockRootProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no beacon block root provider specified",
		},
		{
			name: "SyncCommitteeMessagesSubmitterMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no sync committee messages submitter specified",
		},
		{
			name: "ValidatingAccountsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no validating accounts provider specified",
		},
		{
			name: "SyncCommitteeRootSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no sync committee root signer specified",
		},
		{
			name: "SyncCommitteeSelectionSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no sync committee selection signer specified",
		},
		{
			name: "SynccommitteeSubscriptionsSubmitterMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
			},
			err: "problem with parameters: no sync committee subscriptions submitter specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			_, err := standard.New(ctx, test.params...)
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
