// Copyright © 2026 Attestant Limited.
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

package standard

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mockscheduler "github.com/attestantio/vouch/services/scheduler/mock"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	fileconfidant "github.com/wealdtech/go-majordomo/confidants/file"
	standardmajordomo "github.com/wealdtech/go-majordomo/standard"
)

func TestMinValueWarningOncePerChange(t *testing.T) {
	ctx := context.Background()
	const warning = "Execution configuration min_value is ignored for Gloas proposals; set epbs_builder_config.min_bid instead"
	const withMinValue = `{"version":2,"min_value":"0.1"}`
	const withoutMinValue = `{"version":2}`

	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(mock.NewSpecProvider()),
	)
	require.NoError(t, err)
	majordomoSvc, err := standardmajordomo.New(ctx)
	require.NoError(t, err)
	fileConfidant, err := fileconfidant.New(ctx)
	require.NoError(t, err)
	require.NoError(t, majordomoSvc.RegisterConfidant(ctx, fileConfidant))

	configFile := filepath.Join(t.TempDir(), "config.json")
	writeConfig := func(config string) {
		require.NoError(t, os.WriteFile(configFile, []byte(config), 0o600))
	}
	writeConfig(withMinValue)

	capture := logger.NewLogCapture()
	s, err := New(ctx,
		WithMonitor(nullmetrics.New()),
		WithMajordomo(majordomoSvc),
		WithScheduler(mockscheduler.New()),
		WithListenAddress("0.0.0.0:13533"),
		WithChainTime(chainTime),
		WithConfigURL(fmt.Sprintf("file://%s", configFile)),
		WithFallbackFeeRecipient(bellatrix.ExecutionAddress{0x01}),
		WithFallbackGasLimit(10000000),
		WithValidatingAccountsProvider(mockaccountmanager.NewValidatingAccountsProvider()),
		WithAccountsProvider(mockaccountmanager.NewAccountsProvider()),
		WithValidatorsProvider(mock.NewValidatorsProvider()),
		WithValidatorRegistrationSigner(mocksigner.New()),
		WithReleaseVersion("test"),
		WithBuilderBidProvider(mock.BuilderBidProvider{}),
	)
	require.NoError(t, err)

	warnings := func() int {
		count := 0
		for _, entry := range capture.Entries() {
			if entry["message"] == warning && entry["level"] == "warn" {
				count++
			}
		}

		return count
	}

	// New loads the configuration once; refetching the same configuration does not warn again.
	s.fetchExecutionConfig(ctx)
	s.fetchExecutionConfig(ctx)
	require.Equal(t, 1, warnings())

	// Clearing the condition and then restoring it warns again.
	writeConfig(withoutMinValue)
	s.fetchExecutionConfig(ctx)
	require.Equal(t, 1, warnings())
	writeConfig(withMinValue)
	s.fetchExecutionConfig(ctx)
	require.Equal(t, 2, warnings())
}
