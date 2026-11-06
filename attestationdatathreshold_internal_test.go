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

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	mockconsensusclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	vouchmock "github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// thresholdStyles are the attestation data styles with a threshold, and the key of each.
var thresholdStyles = []struct {
	style string
	key   string
}{
	{"majority", "strategies.attestationdata.majority.threshold"},
	{"combinedmajority", "strategies.attestationdata.combinedmajority.threshold"},
}

// useAttestationDataProviders configures the given attestation data style over the given providers,
// each behind its own mock beacon node.  Tests set the threshold keys themselves.
func useAttestationDataProviders(t *testing.T, style string, providers ...eth2client.AttestationDataProvider) {
	t.Helper()

	addresses := make([]string, 0, len(providers))
	for i, provider := range providers {
		client, err := mockconsensusclient.New(context.Background())
		require.NoError(t, err)
		client.AttestationDataFunc = provider.AttestationData
		address := fmt.Sprintf("http://attestation-data-threshold-%s-%d.test", style, i)
		addresses = append(addresses, address)
		knownClientsMu.Lock()
		knownClients[address] = client
		knownClientsMu.Unlock()
	}
	viper.Set("strategies.attestationdata.style", style)
	viper.Set("strategies.attestationdata.beacon-node-addresses", addresses)
	viper.Set("timeout", 2*time.Second)
	viper.Set("process-concurrency", int64(1))
	t.Cleanup(func() {
		viper.Reset()
		knownClientsMu.Lock()
		for _, address := range addresses {
			delete(knownClients, address)
		}
		knownClientsMu.Unlock()
	})
}

func selectAttestationDataProviderForTest(t *testing.T) (eth2client.AttestationDataProvider, error) {
	t.Helper()

	ctx := context.Background()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(vouchmock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(vouchmock.NewSpecProvider()),
	)
	require.NoError(t, err)

	return selectAttestationDataProvider(ctx, null.New(), chainTime, mockcache.New(map[phase0.Root]phase0.Slot{}).(cache.Service))
}

// captureLog sends the main package's log output to the returned capture.
func captureLog(t *testing.T) *logger.LogCapture {
	t.Helper()

	original := log
	originalGlobal := zerologger.Logger
	originalLevel := zerolog.GlobalLevel()
	t.Cleanup(func() {
		log = original
		zerologger.Logger = originalGlobal
		zerolog.SetGlobalLevel(originalLevel)
	})
	// NewLogCapture also replaces the global logger, which the strategies log to.
	capture := logger.NewLogCapture()
	log = zerolog.New(capture)

	return capture
}

// TestAttestationDataStrategyThresholdKeys proves each style reads its own threshold key and not the other's.
// Two of the three nodes agree, so a threshold of 3 fails and a threshold of 2 passes.
func TestAttestationDataStrategyThresholdKeys(t *testing.T) {
	tests := []struct {
		name  string
		style string
		// key is the threshold key set to 3.
		key string
		err string
	}{
		{
			name:  "MajorityEnforcesMajorityThreshold",
			style: "majority",
			key:   "strategies.attestationdata.majority.threshold",
			err:   "majority attestation data count of 2 lower than threshold 3",
		},
		{
			name:  "MajorityIgnoresCombinedMajorityThreshold",
			style: "majority",
			key:   "strategies.attestationdata.combinedmajority.threshold",
		},
		{
			name:  "CombinedMajorityEnforcesCombinedMajorityThreshold",
			style: "combinedmajority",
			key:   "strategies.attestationdata.combinedmajority.threshold",
			err:   "majority attestation data count of 2 lower than threshold 3",
		},
		{
			name:  "CombinedMajorityIgnoresMajorityThreshold",
			style: "combinedmajority",
			key:   "strategies.attestationdata.majority.threshold",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			useAttestationDataProviders(t, test.style,
				vouchmock.NewAttestationDataProvider(),
				vouchmock.NewAttestationDataProvider(),
				vouchmock.NewCustomAttestationDataProvider(1, true),
			)
			viper.Set(test.key, 3)

			provider, err := selectAttestationDataProviderForTest(t)
			require.NoError(t, err)
			response, err := provider.AttestationData(context.Background(), &api.AttestationDataOpts{Slot: 12345, CommitteeIndex: 3})
			if test.err != "" {
				require.EqualError(t, err, test.err)

				return
			}
			require.NoError(t, err)
			require.Equal(t, phase0.Slot(12345), response.Data.Slot)
		})
	}
}

// TestAttestationDataThresholdMalformed proves a threshold that is set but is not a non-negative integer stops startup.
func TestAttestationDataThresholdMalformed(t *testing.T) {
	tests := []struct {
		name string
		// yaml is the config file contents for the key, with %s for the style.
		yaml string
		// env is the value of the key's environment variable.
		env   string
		value string
	}{
		{name: "EmptyInConfigFile", yaml: "strategies:\n  attestationdata:\n    %s:\n      threshold: \"\"\n", value: ""},
		{name: "WordInConfigFile", yaml: "strategies:\n  attestationdata:\n    %s:\n      threshold: two\n", value: "two"},
		{name: "NegativeInConfigFile", yaml: "strategies:\n  attestationdata:\n    %s:\n      threshold: -1\n", value: "-1"},
		{name: "FractionInConfigFile", yaml: "strategies:\n  attestationdata:\n    %s:\n      threshold: 1.5\n", value: "1.5"},
		{name: "WordInEnvironment", env: "two", value: "two"},
		{name: "TrailingNewlineInEnvironment", env: "3\n", value: "3\n"},
	}

	for _, thresholdStyle := range thresholdStyles {
		for i, test := range tests {
			t.Run(thresholdStyle.style+"/"+test.name, func(t *testing.T) {
				useAttestationDataProviders(t, thresholdStyle.style,
					vouchmock.NewAttestationDataProvider(),
					vouchmock.NewAttestationDataProvider(),
					vouchmock.NewAttestationDataProvider(),
				)
				if test.yaml != "" {
					viper.SetConfigType("yaml")
					require.NoError(t, viper.ReadConfig(strings.NewReader(fmt.Sprintf(test.yaml, thresholdStyle.style))))
				} else {
					// A prefix of its own keeps the test clear of any real VOUCH_ variables.
					prefix := fmt.Sprintf("VOUCHTHRESHOLDTEST%s%d", strings.ToUpper(thresholdStyle.style), i)
					viper.SetEnvPrefix(prefix)
					viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
					viper.AutomaticEnv()
					t.Setenv(prefix+"_"+strings.NewReplacer(".", "_").Replace(strings.ToUpper(thresholdStyle.key)), test.env)
				}

				_, err := selectAttestationDataProviderForTest(t)
				require.EqualError(t, err, fmt.Sprintf("%s: invalid value %q; must be a non-negative integer", thresholdStyle.key, test.value))
			})
		}
	}
}

// TestAttestationDataThresholdLogs proves the effective threshold is logged, and that a threshold
// that enforces no minimum is warned about when there is more than one beacon node.
func TestAttestationDataThresholdLogs(t *testing.T) {
	tests := []struct {
		name  string
		nodes int
		// threshold is the configured value, nil for unset.
		threshold *int
		// effective is the threshold the strategy runs with.
		effective int
		warns     bool
	}{
		{name: "UnsetWithManyNodes", nodes: 3, effective: 0, warns: true},
		{name: "ZeroWithManyNodes", nodes: 3, threshold: new(0), effective: 0, warns: true},
		{name: "OneWithManyNodes", nodes: 3, threshold: new(1), effective: 1, warns: true},
		{name: "TwoWithManyNodes", nodes: 3, threshold: new(2), effective: 2},
		{name: "ThreeWithManyNodes", nodes: 3, threshold: new(3), effective: 3},
		{name: "UnsetWithTwoNodes", nodes: 2, effective: 0, warns: true},
		{name: "TwoWithTwoNodes", nodes: 2, threshold: new(2), effective: 2},
		{name: "UnsetWithOneNode", nodes: 1, effective: 0},
		{name: "OneWithOneNode", nodes: 1, threshold: new(1), effective: 1},
	}

	for _, thresholdStyle := range thresholdStyles {
		for _, test := range tests {
			t.Run(thresholdStyle.style+"/"+test.name, func(t *testing.T) {
				capture := captureLog(t)
				providers := make([]eth2client.AttestationDataProvider, test.nodes)
				for i := range providers {
					providers[i] = vouchmock.NewAttestationDataProvider()
				}
				useAttestationDataProviders(t, thresholdStyle.style, providers...)
				if test.threshold != nil {
					viper.Set(thresholdStyle.key, *test.threshold)
				}

				_, err := selectAttestationDataProviderForTest(t)
				require.NoError(t, err)

				require.True(t, capture.HasLog(map[string]any{
					"level":     "info",
					"message":   "Attestation data strategy threshold",
					"key":       thresholdStyle.key,
					"threshold": test.effective,
				}))
				warnings := 0
				for _, entry := range capture.Entries() {
					if entry["level"] == "warn" {
						warnings++
					}
				}
				if !test.warns {
					require.Zero(t, warnings)

					return
				}
				require.Equal(t, 1, warnings)
				require.True(t, capture.HasLog(map[string]any{
					"level":     "warn",
					"message":   thresholdStyle.key + " is below 2, so it enforces no minimum number of agreeing beacon nodes; set it to 2 or more",
					"key":       thresholdStyle.key,
					"threshold": test.effective,
				}))
			})
		}
	}
}

// TestAttestationDataThresholdAboveInt proves a threshold too large for an int is rejected as above the node count,
// rather than wrapping to a negative number.
func TestAttestationDataThresholdAboveInt(t *testing.T) {
	for _, thresholdStyle := range thresholdStyles {
		t.Run(thresholdStyle.style, func(t *testing.T) {
			useAttestationDataProviders(t, thresholdStyle.style,
				vouchmock.NewAttestationDataProvider(),
				vouchmock.NewAttestationDataProvider(),
				vouchmock.NewAttestationDataProvider(),
			)
			viper.Set(thresholdStyle.key, "9223372036854775808")

			_, err := selectAttestationDataProviderForTest(t)
			require.EqualError(t, err, fmt.Sprintf("failed to start %s attestation data strategy: problem with parameters: threshold cannot be higher than number of data providers", thresholdStyle.style))
		})
	}
}
