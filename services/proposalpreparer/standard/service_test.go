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

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	mockblockrelay "github.com/attestantio/vouch/services/blockrelay/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	prometheusmetrics "github.com/attestantio/vouch/services/metrics/prometheus"
	"github.com/attestantio/vouch/services/proposalpreparer/standard"
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

	mockValidatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	mockProposalPreparationsSubmitters := []eth2client.ProposalPreparationsSubmitter{mock.NewProposalPreparationsSubmitter()}
	mockBlockRelay := mockblockrelay.New()

	prometheusMetrics, err := prometheusmetrics.New(ctx,
		prometheusmetrics.WithAddress(":12345"),
		prometheusmetrics.WithChainTime(chainTime),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		params   []standard.Parameter
		err      string
		logEntry string
	}{
		{
			name: "MonitorNil",
			params: []standard.Parameter{
				standard.WithMonitor(nil),
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithProposalPreparationsSubmitters(mockProposalPreparationsSubmitters),
				standard.WithExecutionConfigProvider(mockBlockRelay),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ChainTimeServiceMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithProposalPreparationsSubmitters(mockProposalPreparationsSubmitters),
				standard.WithExecutionConfigProvider(mockBlockRelay),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "ValidatingAccountsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithChainTimeService(chainTime),
				standard.WithProposalPreparationsSubmitters(mockProposalPreparationsSubmitters),
				standard.WithExecutionConfigProvider(mockBlockRelay),
			},
			err: "problem with parameters: no validating accounts provider specified",
		},
		{
			name: "ExecConfigProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithProposalPreparationsSubmitters(mockProposalPreparationsSubmitters),
			},
			err: "problem with parameters: no execution configuration provider specified",
		},
		{
			name: "ProposalPreparationsSubmittersMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithExecutionConfigProvider(mockBlockRelay),
			},
			err: "problem with parameters: no proposal preparations submitters specified",
		},
		{
			name: "ProposalPreparationsSubmittersempty",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithProposalPreparationsSubmitters([]eth2client.ProposalPreparationsSubmitter{}),
				standard.WithExecutionConfigProvider(mockBlockRelay),
			},
			err: "problem with parameters: no proposal preparations submitters specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithMonitor(prometheusMetrics),
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithProposalPreparationsSubmitters(mockProposalPreparationsSubmitters),
				standard.WithExecutionConfigProvider(mockBlockRelay),
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
