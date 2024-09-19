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

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	"github.com/attestantio/vouch/services/blockrelay/standard"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mockscheduler "github.com/attestantio/vouch/services/scheduler/mock"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	directconfidant "github.com/wealdtech/go-majordomo/confidants/direct"
	standardmajordomo "github.com/wealdtech/go-majordomo/standard"
)

func TestService(t *testing.T) {
	ctx := context.Background()

	zerolog.SetGlobalLevel(zerolog.Disabled)

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	mockValidatorsProvider := mock.NewValidatorsProvider()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	mockValidatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	mockAccountsProvider := mockaccountmanager.NewAccountsProvider()

	monitor := nullmetrics.New()

	majordomoSvc, err := standardmajordomo.New(ctx)
	require.NoError(t, err)
	directConfidant, err := directconfidant.New(ctx)
	require.NoError(t, err)
	err = majordomoSvc.RegisterConfidant(ctx, directConfidant)
	require.NoError(t, err)

	mockScheduler := mockscheduler.New()

	listenAddress := "0.0.0.0:13532"
	configURL := "file:/tmp/execconfig.json"
	fallbackFeeRecipient := bellatrix.ExecutionAddress{0x01}
	fallbackGasLimit := uint64(10000000)
	mockSigner := mocksigner.New()

	builderBidProvider := mock.BuilderBidProvider{}

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
				standard.WithMonitor(nil),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "MajordomoMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(nil),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: no majordomo specified",
		},
		{
			name: "SchedulerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(nil),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: no scheduler specified",
		},
		{
			name: "ListenAddressMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(""),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: no listen address specified",
		},
		{
			name: "ListenAddressMalformed",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress("abc"),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: listen address malformed",
		},
		{
			name: "ChainTimeMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(nil),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: no chaintime specified",
		},
		{
			name: "FallbackFeeRecipientZero",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(bellatrix.ExecutionAddress{}),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: no fallback fee recipient specified",
		},
		{
			name: "FallbackGasLimitZero",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(0),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: no fallback gas limit specified",
		},
		{
			name: "AccountsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: no accounts provider specified",
		},
		{
			name: "ValidatorsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithLogResults(true),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: no validators provider specified",
		},
		{
			name: "ValidatingAccountsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(nil),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: no validating accounts provider specified",
		},
		{
			name: "ValidatorRegistrationSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(nil),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: no validator registration signer specified",
		},
		{
			name: "ReleaseVersionMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithLogResults(true),
				standard.WithBuilderBidProvider(builderBidProvider),
			},
			err: "problem with parameters: no release version specified",
		},
		{
			name: "BuilderBidProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithLogResults(true),
				standard.WithReleaseVersion("test"),
			},
			err: "problem with parameters: no builder bid provider specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithAccountsProvider(mockAccountsProvider),
				standard.WithValidatorsProvider(mockValidatorsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithLogResults(true),
				standard.WithReleaseVersion("test"),
				standard.WithBuilderBidProvider(builderBidProvider),
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
