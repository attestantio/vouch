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

	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	"github.com/attestantio/vouch/services/attester/standard"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	prometheusmetrics "github.com/attestantio/vouch/services/metrics/prometheus"
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
	specProvider := mock.NewSpecProvider()
	attestationDataProvider := mock.NewAttestationDataProvider()
	attestationsSubmitter := mock.NewAttestationsSubmitter()
	beaconAttestationsSigner := mocksigner.New()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	validatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	prometheusMetrics, err := prometheusmetrics.New(ctx,
		prometheusmetrics.WithAddress(":12345"),
	)
	require.NoError(t, err)

	majordomoSvc, err := standardmajordomo.New(ctx)
	require.NoError(t, err)
	directConfidant, err := directconfidant.New(ctx)
	require.NoError(t, err)
	err = majordomoSvc.RegisterConfidant(ctx, directConfidant)
	require.NoError(t, err)

	tests := []struct {
		name       string
		params     []standard.Parameter
		err        string
		logEntries []string
	}{
		{
			name: "MonitorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nil),
				standard.WithProcessConcurrency(1),
				standard.WithChainTime(chainTime),
				standard.WithSpecProvider(specProvider),
				standard.WithAttestationDataProvider(attestationDataProvider),
				standard.WithAttestationsSubmitter(attestationsSubmitter),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithBeaconAttestationsSigner(beaconAttestationsSigner),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ProcessConcurrency0",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithProcessConcurrency(0),
				standard.WithChainTime(chainTime),
				standard.WithSpecProvider(specProvider),
				standard.WithAttestationDataProvider(attestationDataProvider),
				standard.WithAttestationsSubmitter(attestationsSubmitter),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithBeaconAttestationsSigner(beaconAttestationsSigner),
			},
			err: "problem with parameters: no process concurrency specified",
		},
		{
			name: "ChainTimeMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithProcessConcurrency(1),
				standard.WithChainTime(nil),
				standard.WithSpecProvider(specProvider),
				standard.WithAttestationDataProvider(attestationDataProvider),
				standard.WithAttestationsSubmitter(attestationsSubmitter),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithBeaconAttestationsSigner(beaconAttestationsSigner),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "SpecProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithProcessConcurrency(1),
				standard.WithChainTime(chainTime),
				standard.WithSpecProvider(nil),
				standard.WithAttestationDataProvider(attestationDataProvider),
				standard.WithAttestationsSubmitter(attestationsSubmitter),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithBeaconAttestationsSigner(beaconAttestationsSigner),
			},
			err: "problem with parameters: no spec provider specified",
		},
		{
			name: "AttestationDataProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithProcessConcurrency(1),
				standard.WithChainTime(chainTime),
				standard.WithSpecProvider(specProvider),
				standard.WithAttestationDataProvider(nil),
				standard.WithAttestationsSubmitter(attestationsSubmitter),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithBeaconAttestationsSigner(beaconAttestationsSigner),
			},
			err: "problem with parameters: no attestation data provider specified",
		},
		{
			name: "AttestationsSubmitterMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithProcessConcurrency(1),
				standard.WithChainTime(chainTime),
				standard.WithSpecProvider(specProvider),
				standard.WithAttestationDataProvider(attestationDataProvider),
				standard.WithAttestationsSubmitter(nil),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithBeaconAttestationsSigner(beaconAttestationsSigner),
			},
			err: "problem with parameters: no attestations submitter specified",
		},
		{
			name: "ValidatingAccountsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithProcessConcurrency(1),
				standard.WithChainTime(chainTime),
				standard.WithSpecProvider(specProvider),
				standard.WithAttestationDataProvider(attestationDataProvider),
				standard.WithAttestationsSubmitter(attestationsSubmitter),
				standard.WithValidatingAccountsProvider(nil),
				standard.WithBeaconAttestationsSigner(beaconAttestationsSigner),
			},
			err: "problem with parameters: no validating accounts provider specified",
		},
		{
			name: "BeaconAttestationsSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithProcessConcurrency(1),
				standard.WithChainTime(chainTime),
				standard.WithSpecProvider(specProvider),
				standard.WithAttestationDataProvider(attestationDataProvider),
				standard.WithAttestationsSubmitter(attestationsSubmitter),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithBeaconAttestationsSigner(nil),
			},
			err: "problem with parameters: no beacon attestations signer specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithProcessConcurrency(1),
				standard.WithChainTime(chainTime),
				standard.WithSpecProvider(specProvider),
				standard.WithAttestationDataProvider(attestationDataProvider),
				standard.WithAttestationsSubmitter(attestationsSubmitter),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithBeaconAttestationsSigner(beaconAttestationsSigner),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			_, err := standard.New(ctx, test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
			for _, entry := range test.logEntries {
				capture.AssertHasEntry(t, entry)
			}
		})
	}
}
