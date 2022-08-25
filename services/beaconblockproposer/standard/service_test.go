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
	mockaccountsprovider "github.com/attestantio/vouch/services/accountmanager/mock"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/beaconblockproposer/standard"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	mockfeerecipientprovider "github.com/attestantio/vouch/services/feerecipientprovider/mock"
	staticgraffitiprovider "github.com/attestantio/vouch/services/graffitiprovider/static"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	slotDuration := 12 * time.Second
	slotsPerEpoch := uint64(32)
	genesisTimeProvider := mock.NewGenesisTimeProvider(genesisTime)
	slotDurationProvider := mock.NewSlotDurationProvider(slotDuration)
	slotsPerEpochProvider := mock.NewSlotsPerEpochProvider(slotsPerEpoch)

	validatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	signer := mocksigner.New()

	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisTimeProvider(genesisTimeProvider),
		standardchaintime.WithSlotDurationProvider(slotDurationProvider),
		standardchaintime.WithSlotsPerEpochProvider(slotsPerEpochProvider),
	)

	consensusClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	feeRecipientsProvider := mockfeerecipientprovider.New()
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
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithFeeRecipientProvider(feeRecipientsProvider),
				standard.WithBeaconBlockSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ProposalDataProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithFeeRecipientProvider(feeRecipientsProvider),
				standard.WithBeaconBlockSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
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
				standard.WithFeeRecipientProvider(feeRecipientsProvider),
				standard.WithBeaconBlockSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "ValidatingAccountsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithChainTimeService(chainTime),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithFeeRecipientProvider(feeRecipientsProvider),
				standard.WithBeaconBlockSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
			},
			err: "problem with parameters: no validating accounts provider specified",
		},
		{
			name: "FeeRecipientProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithBeaconBlockSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
			},
			err: "problem with parameters: no fee recipient provider specified",
		},
		{
			name: "BeaconBlockSubmitterMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithFeeRecipientProvider(feeRecipientsProvider),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
			},
			err: "problem with parameters: no beacon block submitter specified",
		},
		{
			name: "RANDAORevealSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithFeeRecipientProvider(feeRecipientsProvider),
				standard.WithBeaconBlockSubmitter(consensusClient),
				standard.WithBeaconBlockSigner(signer),
			},
			err: "problem with parameters: no RANDAO reveal signer specified",
		},
		{
			name: "BeaconBlockSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithFeeRecipientProvider(feeRecipientsProvider),
				standard.WithBeaconBlockSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
			},
			err: "problem with parameters: no beacon block signer specified",
		},
		{
			name: "GoodWithOptionals",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithFeeRecipientProvider(feeRecipientsProvider),
				standard.WithBeaconBlockSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
				standard.WithGraffitiProvider(graffitiProvider),
			},
		},
		{
			name: "BlindedProposalDataProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithFeeRecipientProvider(feeRecipientsProvider),
				standard.WithBeaconBlockSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
				standard.WithBlockAuctioneer(blockAuctioneer),
				standard.WithExecutionChainHeadProvider(cacheService.(cache.ExecutionChainHeadProvider)),
			},
			err: "problem with parameters: no blinded proposal data provider specified",
		},
		{
			name: "ExecutionChainHeadProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithFeeRecipientProvider(feeRecipientsProvider),
				standard.WithBeaconBlockSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
				standard.WithBlockAuctioneer(blockAuctioneer),
				standard.WithBlindedProposalDataProvider(consensusClient),
			},
			err: "problem with parameters: no execution chain head provider specified",
		},
		{
			name: "GoodWithAuctioneer",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithFeeRecipientProvider(feeRecipientsProvider),
				standard.WithBeaconBlockSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(signer),
				standard.WithBlockAuctioneer(blockAuctioneer),
				standard.WithBlindedProposalDataProvider(consensusClient),
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
func TestProposeNoRANDAOReveal(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()

	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisTimeProvider(mock.NewGenesisTimeProvider(time.Now())),
		standardchaintime.WithSlotDurationProvider(mock.NewSlotDurationProvider(12*time.Second)),
		standardchaintime.WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
	)
	require.NoError(t, err)

	s, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.TraceLevel),
		standard.WithMonitor(nullmetrics.New(ctx)),
		standard.WithProposalDataProvider(mock.NewBeaconBlockProposalProvider()),
		standard.WithChainTimeService(chainTime),
		standard.WithValidatingAccountsProvider(mockaccountsprovider.NewValidatingAccountsProvider()),
		standard.WithFeeRecipientProvider(mockfeerecipientprovider.New()),
		standard.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
		standard.WithRANDAORevealSigner(mocksigner.New()),
		standard.WithBeaconBlockSigner(mocksigner.New()),
	)
	require.NoError(t, err)

	s.Propose(ctx, &beaconblockproposer.Duty{})
	capture.AssertHasEntry(t, "Missing RANDAO reveal")
}
