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

	mockblockauctioneer "github.com/attestantio/go-block-relay/services/blockauctioneer/mock"
	mockconsensusclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/beaconblockproposer/standard"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	staticgraffitiprovider "github.com/attestantio/vouch/services/graffitiprovider/static"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func duty(randaoReveal phase0.BLSSignature, account e2wtypes.Account) *beaconblockproposer.Duty {
	duty := &beaconblockproposer.Duty{}
	duty.SetRandaoReveal(randaoReveal)
	duty.SetAccount(account)
	return duty
}

func TestPropose(t *testing.T) {
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

	// Create an account.
	require.NoError(t, e2types.InitBLS())
	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := hd.CreateWallet(ctx, "test wallet", []byte("pass"), store, encryptor, make([]byte, 64))
	require.NoError(t, err)
	require.Nil(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, []byte("pass")))
	account, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(context.Background(), "test account", []byte("pass"))
	require.NoError(t, err)

	tests := []struct {
		name string
		data *beaconblockproposer.Duty
		errs []map[string]any
	}{
		{
			name: "Nil",
			errs: []map[string]any{
				{
					"message": "Invalid duty",
					"error":   "no duty supplied",
				},
			},
		},
		{
			name: "Empty",
			data: duty(phase0.BLSSignature{}, nil),
			errs: []map[string]any{
				{
					"message": "Invalid duty",
					"error":   "duty missing RANDAO reveal",
				},
			},
		},
		{
			name: "AccountMissing",
			data: duty(phase0.BLSSignature{0x01}, nil),
			errs: []map[string]any{
				{
					"message": "Invalid duty",
					"error":   "duty missing account",
				},
			},
		},
		{
			name: "Good",
			data: duty(phase0.BLSSignature{0x01}, account),
			errs: []map[string]any{
				{
					"message": "Submitted proposal",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			s, err := standard.New(ctx,
				standard.WithMonitor(nullmetrics.New()),
				standard.WithProposalDataProvider(consensusClient),
				standard.WithChainTime(chainTime),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithProposalSubmitter(consensusClient),
				standard.WithRANDAORevealSigner(signer),
				standard.WithGraffitiProvider(graffitiProvider),
				standard.WithBeaconBlockSigner(signer),
				standard.WithBlobSidecarSigner(signer),
				standard.WithBlockAuctioneer(blockAuctioneer),
				standard.WithExecutionChainHeadProvider(cacheService.(cache.ExecutionChainHeadProvider)),
			)
			require.NoError(t, err)

			s.Propose(ctx, test.data)

			for _, err := range test.errs {
				require.True(t, capture.HasLog(err))
			}
		})
	}
}
