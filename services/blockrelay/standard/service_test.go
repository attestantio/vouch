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

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	"github.com/attestantio/vouch/services/blockrelay/standard"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	prometheusmetrics "github.com/attestantio/vouch/services/metrics/prometheus"
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
	slotDuration := 12 * time.Second
	slotsPerEpoch := uint64(32)
	genesisTimeProvider := mock.NewGenesisTimeProvider(genesisTime)
	slotDurationProvider := mock.NewSlotDurationProvider(slotDuration)
	slotsPerEpochProvider := mock.NewSlotsPerEpochProvider(slotsPerEpoch)

	mockValidatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()

	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithGenesisTimeProvider(genesisTimeProvider),
		standardchaintime.WithSlotDurationProvider(slotDurationProvider),
		standardchaintime.WithSlotsPerEpochProvider(slotsPerEpochProvider),
	)
	require.NoError(t, err)

	prometheusMetrics, err := prometheusmetrics.New(ctx,
		prometheusmetrics.WithAddress(":12345"),
		prometheusmetrics.WithChainTime(chainTime),
	)
	require.NoError(t, err)

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
				standard.WithTimeout(time.Second),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "TimeoutZero",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithTimeout(0),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "MajordomoMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithTimeout(time.Second),
				standard.WithMajordomo(nil),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
			},
			err: "problem with parameters: no majordomo specified",
		},
		{
			name: "SchedulerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithTimeout(time.Second),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(nil),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
			},
			err: "problem with parameters: no scheduler specified",
		},
		{
			name: "ListenAddressMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithTimeout(time.Second),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(""),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
			},
			err: "problem with parameters: no listen address specified",
		},
		{
			name: "ListenAddressMalformed",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithTimeout(time.Second),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress("abc"),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
			},
			err: "problem with parameters: listen address malformed",
		},
		{
			name: "ChainTimeMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithTimeout(time.Second),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(nil),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
			},
			err: "problem with parameters: no chaintime specified",
		},
		{
			name: "FallbackFeeRecipientZero",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithTimeout(time.Second),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(bellatrix.ExecutionAddress{}),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
			},
			err: "problem with parameters: no fallback fee recipient specified",
		},
		{
			name: "FallbackGasLimitZero",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithTimeout(time.Second),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(0),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
			},
			err: "problem with parameters: no fallback gas limit specified",
		},
		{
			name: "ValidatingAccountsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithTimeout(time.Second),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithValidatingAccountsProvider(nil),
				standard.WithValidatorRegistrationSigner(mockSigner),
			},
			err: "problem with parameters: no validating accounts provider specified",
		},
		{
			name: "ValidatorRegistrationSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithTimeout(time.Second),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(nil),
			},
			err: "problem with parameters: no validator registration signer specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithTimeout(time.Second),
				standard.WithMajordomo(majordomoSvc),
				standard.WithScheduler(mockScheduler),
				standard.WithListenAddress(listenAddress),
				standard.WithChainTime(chainTime),
				standard.WithConfigURL(configURL),
				standard.WithFallbackFeeRecipient(fallbackFeeRecipient),
				standard.WithFallbackGasLimit(fallbackGasLimit),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithValidatorRegistrationSigner(mockSigner),
				standard.WithLogResults(true),
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
