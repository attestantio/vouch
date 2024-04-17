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
)

func NoTestService(t *testing.T) {
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
		prometheusmetrics.WithChainTime(chainTime),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		err      string
		logEntry string
	}{
		{
			name: "Nil",
			err:  "problem with parameters: no monitor specified",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			_, err := standard.New(ctx,
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMetrics),
				standard.WithProcessConcurrency(1),
				standard.WithChainTimeService(chainTime),
				standard.WithSpecProvider(specProvider),
				standard.WithAttestationDataProvider(attestationDataProvider),
				standard.WithAttestationsSubmitter(attestationsSubmitter),
				standard.WithValidatingAccountsProvider(validatingAccountsProvider),
				standard.WithBeaconAttestationsSigner(beaconAttestationsSigner),
			)
			require.NoError(t, err)

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
