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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	"github.com/attestantio/vouch/services/blockrelay/standard"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mockscheduler "github.com/attestantio/vouch/services/scheduler/mock"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/attestantio/vouch/testutil"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	nd "github.com/wealdtech/go-eth2-wallet-nd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	directconfidant "github.com/wealdtech/go-majordomo/confidants/direct"
	fileconfidant "github.com/wealdtech/go-majordomo/confidants/file"
	standardmajordomo "github.com/wealdtech/go-majordomo/standard"
)

func TestProposerConfig(t *testing.T) {
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

	mockValidatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	mockAccountsProvider := mockaccountmanager.NewAccountsProvider()
	mockValidatorsProvider := mock.NewValidatorsProvider()
	require.NoError(t, e2types.InitBLS())
	store := scratch.New()
	require.NoError(t, e2wallet.UseStore(store))
	testWallet, err := nd.CreateWallet(context.Background(), "Test wallet", store, keystorev4.New())
	require.NoError(t, err)
	require.NoError(t, testWallet.(e2wtypes.WalletLocker).Unlock(context.Background(), nil))
	viper.Set("passphrase", "pass")
	testAccount, err := testWallet.(e2wtypes.WalletAccountImporter).ImportAccount(context.Background(),
		"Interop 0",
		testutil.HexToBytes("0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866"),
		[]byte("pass"),
	)
	require.NoError(t, err)
	mockValidatingAccountsProvider.AddAccount(1, testAccount)

	majordomoSvc, err := standardmajordomo.New(ctx)
	require.NoError(t, err)
	fileConfidant, err := fileconfidant.New(ctx)
	require.NoError(t, err)
	require.NoError(t, majordomoSvc.RegisterConfidant(ctx, fileConfidant))
	directConfidant, err := directconfidant.New(ctx)
	require.NoError(t, err)
	require.NoError(t, majordomoSvc.RegisterConfidant(ctx, directConfidant))

	mockScheduler := mockscheduler.New()

	listenAddress := "0.0.0.0:13532"
	mockSigner := mocksigner.New()

	base, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(base)
	configFile := filepath.Join(base, "config.json")
	require.NoError(t, os.WriteFile(configFile, []byte(`{"default_config":{"fee_recipient":"0x0200000000000000000000000000000000000000","gas_limit":"20000000","builder":{"enabled":false}}}`), 0o600))
	badConfigFile := filepath.Join(base, "badconfig.json")
	require.NoError(t, os.WriteFile(badConfigFile, []byte(`bad`), 0o600))

	tests := []struct {
		name           string
		params         []standard.Parameter
		proposerConfig string
		err            string
		logEntries     []map[string]interface{}
	}{
		{
			name: "Fallback",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithFallbackFeeRecipient(bellatrix.ExecutionAddress{0x01}),
				standard.WithFallbackGasLimit(10000000),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(mock.BuilderBidProvider{}),
			},
			proposerConfig: `{"fee_recipient":"0x0100000000000000000000000000000000000000","relays":[]}`,
		},
		{
			name: "File",
			params: []standard.Parameter{
				standard.WithMonitor(nullmetrics.New()),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(fmt.Sprintf("file://%s", configFile)),
				standard.WithFallbackFeeRecipient(bellatrix.ExecutionAddress{0x01}),
				standard.WithFallbackGasLimit(10000000),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(mock.BuilderBidProvider{}),
			},
			proposerConfig: `{"fee_recipient":"0x0200000000000000000000000000000000000000","relays":[]}`,
			logEntries: []map[string]interface{}{
				{
					"message": "Obtained configuration",
				},
			},
		},
		{
			name: "BadFile",
			params: []standard.Parameter{
				standard.WithMonitor(nullmetrics.New()),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(fmt.Sprintf("file://%s", badConfigFile)),
				standard.WithFallbackFeeRecipient(bellatrix.ExecutionAddress{0x01}),
				standard.WithFallbackGasLimit(10000000),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(mock.BuilderBidProvider{}),
			},
			proposerConfig: `{"fee_recipient":"0x0100000000000000000000000000000000000000","relays":[]}`,
			logEntries: []map[string]interface{}{
				{
					"message": "Failed to obtain execution configuration",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			s, err := standard.New(ctx, test.params...)
			require.NoError(t, err)
			proposerConfig, err := s.ProposerConfig(ctx, testAccount, phase0.BLSPubKey{})
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				data, err := json.Marshal(proposerConfig)
				require.NoError(t, err)
				require.Equal(t, test.proposerConfig, string(data))
			}
			for _, logEntry := range test.logEntries {
				if !capture.HasLog(logEntry) {
					require.Fail(t, fmt.Sprintf("Missing log entry %v in %v", logEntry, capture.Entries()))
				}
			}
		})
	}
}
