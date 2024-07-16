// Copyright © 2021, 2022 Attestant Limited.
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

	mockblockauctioneer "github.com/attestantio/go-block-relay/services/blockauctioneer/mock"
	mockconsensusclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	"github.com/attestantio/vouch/services/beaconblockproposer/standard"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	staticgraffitiprovider "github.com/attestantio/vouch/services/graffitiprovider/static"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
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

	validatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	signer := mocksigner.New()

	consensusClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	graffitiProvider, err := staticgraffitiprovider.New(ctx)
	require.NoError(t, err)
	blockAuctioneer := mockblockauctioneer.New()
	cacheService := mockcache.New(map[phase0.Root]phase0.Slot{})

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
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTime(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithProposalSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
				standard.WithBlobSidecarSigner(signer),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ProposalDataProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithChainTime(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithProposalSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
				standard.WithBlobSidecarSigner(signer),
			},
			err: "problem with parameters: no proposal data provider specified",
		},
		{
			name: "ChainTimeMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithProposalSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
				standard.WithBlobSidecarSigner(signer),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "ValidatingAccountsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithChainTime(chainTime),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithProposalSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
				standard.WithBlobSidecarSigner(signer),
			},
			err: "problem with parameters: no validating accounts provider specified",
		},
		{
			name: "ProposalSubmitterMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTime(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
				standard.WithBlobSidecarSigner(signer),
			},
			err: "problem with parameters: no proposal submitter specified",
		},
		{
			name: "RANDAORevealSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTime(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithProposalSubmitter(consensusClient),
				standard.WithBeaconBlockSigner(signer),
				standard.WithBlobSidecarSigner(signer),
			},
			err: "problem with parameters: no RANDAO reveal signer specified",
		},
		{
			name: "BeaconBlockSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTime(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithProposalSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBlobSidecarSigner(signer),
			},
			err: "problem with parameters: no beacon block signer specified",
		},
		{
			name: "BlobSidecarSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTime(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithProposalSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
			},
			err: "problem with parameters: no blob sidecar signer specified",
		},
		{
			name: "GoodWithOptionals",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTime(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithProposalSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
				standard.WithGraffitiProvider(graffitiProvider),
				standard.WithBlobSidecarSigner(signer),
			},
		},
		{
			name: "ExecutionChainHeadProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTime(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithProposalSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
				standard.WithBlobSidecarSigner(signer),
				standard.WithBlockAuctioneer(blockAuctioneer),
			},
			err: "problem with parameters: no execution chain head provider specified",
		},
		{
			name: "GoodWithAuctioneer",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTime(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithProposalSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
				standard.WithBlobSidecarSigner(signer),
				standard.WithBlockAuctioneer(blockAuctioneer),
				standard.WithExecutionChainHeadProvider(cacheService.(cache.ExecutionChainHeadProvider)),
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
