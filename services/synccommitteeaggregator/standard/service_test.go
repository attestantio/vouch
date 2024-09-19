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
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"testing"
	"time"

	mocketh2client "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	nullsubmitter "github.com/attestantio/vouch/services/submitter/null"
	"github.com/attestantio/vouch/services/synccommitteeaggregator/standard"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	ctx := context.Background()

	specProvider := mock.NewSpecProvider()

	mockSigner := mocksigner.New()
	nullSubmitter, err := nullsubmitter.New(ctx)
	require.NoError(t, err)
	mockETH2Client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	mockValidatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	genesisProvider := mock.NewGenesisProvider(time.Now())
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		params   []standard.Parameter
		err      string
		logEntry string
	}{
		{
			name: "MonitorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithContributionAndProofSigner(mockSigner),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeContributionProvider(mockETH2Client),
				standard.WithSyncCommitteeContributionsSubmitter(nullSubmitter),
				standard.WithChainTime(chainTime),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "SpecProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithContributionAndProofSigner(mockSigner),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeContributionProvider(mockETH2Client),
				standard.WithSyncCommitteeContributionsSubmitter(nullSubmitter),
				standard.WithChainTime(chainTime),
			},
			err: "problem with parameters: no spec provider specified",
		},
		{
			name: "BeaconBlockRootProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithSpecProvider(specProvider),
				standard.WithContributionAndProofSigner(mockSigner),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeContributionProvider(mockETH2Client),
				standard.WithSyncCommitteeContributionsSubmitter(nullSubmitter),
				standard.WithChainTime(chainTime),
			},
			err: "problem with parameters: no beacon block root provider specified",
		},
		{
			name: "ContributionAndProofSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeContributionProvider(mockETH2Client),
				standard.WithSyncCommitteeContributionsSubmitter(nullSubmitter),
				standard.WithChainTime(chainTime),
			},
			err: "problem with parameters: no contribution and proof signer specified",
		},
		{
			name: "ValidatingAccountsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithContributionAndProofSigner(mockSigner),
				standard.WithSyncCommitteeContributionProvider(mockETH2Client),
				standard.WithSyncCommitteeContributionsSubmitter(nullSubmitter),
				standard.WithChainTime(chainTime),
			},
			err: "problem with parameters: no validating accounts provider specified",
		},
		{
			name: "SyncCommitteeContributionProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithContributionAndProofSigner(mockSigner),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeContributionsSubmitter(nullSubmitter),
				standard.WithChainTime(chainTime),
			},
			err: "problem with parameters: no sync committee contribution provider specified",
		},
		{
			name: "SyncCommitteeContributionsSubmitterMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithContributionAndProofSigner(mockSigner),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeContributionProvider(mockETH2Client),
				standard.WithChainTime(chainTime),
			},
			err: "problem with parameters: no sync committee contributions submitter specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithContributionAndProofSigner(mockSigner),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeContributionProvider(mockETH2Client),
				standard.WithSyncCommitteeContributionsSubmitter(nullSubmitter),
				standard.WithChainTime(chainTime),
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
