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

package util_test

import (

	// #nosec G108
	"fmt"
	_ "net/http/pprof"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/attestantio/vouch/util"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestBeaconNodeAddressesPerStrategy(t *testing.T) {
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	tests := []struct {
		name      string
		env       map[string]string
		expected  []string
		envPrefix string
		handler   func() []string
	}{
		{
			name: "ProposingNoStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES": "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":         "3 4",
				"STRATEGIES_BEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES":        "5 6",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":  "7 8",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected:  []string{"1", "2"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORPROPOSING",
			handler:   util.BeaconNodeAddressesForProposing,
		},
		{
			name: "ProposingFirstStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                             "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_STYLE":                              "first",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":         "3 4",
				"STRATEGIES_BEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES":        "5 6",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":  "7 8",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected:  []string{"1", "2", "5", "6"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORPROPOSING",
			handler:   util.BeaconNodeAddressesForProposing,
		},
		{
			name: "ProposingFirstStrategies",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                             "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_STYLE":                              "first",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":         "3 4",
				"STRATEGIES_BEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES":        "5 6",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_STYLE":                       "first",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":  "7 8",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected:  []string{"5", "6", "9", "10"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORPROPOSING",
			handler:   util.BeaconNodeAddressesForProposing,
		},
		{
			name: "ProposingBestStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                             "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_STYLE":                              "best",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":         "3 4",
				"STRATEGIES_BEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES":        "5 6",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":  "7 8",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected:  []string{"1", "2", "3", "4"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORPROPOSING",
			handler:   util.BeaconNodeAddressesForProposing,
		},
		{
			name: "ProposingBestStrategies",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                             "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_STYLE":                              "best",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":         "3 4",
				"STRATEGIES_BEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES":        "5 6",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_STYLE":                       "best",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":  "7 8",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected:  []string{"3", "4", "7", "8"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORPROPOSING",
			handler:   util.BeaconNodeAddressesForProposing,
		},
		{
			name: "ProposingMixedStrategies",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                             "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_STYLE":                              "best",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":         "3 4",
				"STRATEGIES_BEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES":        "5 6",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_STYLE":                       "first",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":  "7 8",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected:  []string{"3", "4", "9", "10"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORPROPOSING",
			handler:   util.BeaconNodeAddressesForProposing,
		},
		{
			name: "ProposingSimpleStrategyWithOverride",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEACON_NODE_ADDRESSES": "3 4",
			},
			// beaconblockproposal resolves to "3 4" from its override;
			// blindedbeaconblockproposal has no override, so falls back to top-level "1 2".
			expected:  []string{"1", "2", "3", "4"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORPROPOSING",
			handler:   util.BeaconNodeAddressesForProposing,
		},
		{
			name: "ProposingSimpleStrategyBothOverridden",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                       "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEACON_NODE_ADDRESSES":        "3 4",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEACON_NODE_ADDRESSES": "5 6",
			},
			expected:  []string{"3", "4", "5", "6"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORPROPOSING",
			handler:   util.BeaconNodeAddressesForProposing,
		},
		{
			name: "ProposingDeduplication",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                       "1 2 1 3 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEACON_NODE_ADDRESSES":        "1 2",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEACON_NODE_ADDRESSES": "2 3",
			},
			expected:  []string{"1", "2", "3"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORPROPOSING",
			handler:   util.BeaconNodeAddressesForProposing,
		},
		{
			name: "BeaconBlockRootNoStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                     "1 2",
				"STRATEGIES_BEACONBLOCKROOT_FIRST_BEACON_NODE_ADDRESSES":    "3 4",
				"STRATEGIES_BEACONBLOCKROOT_LATEST_BEACON_NODE_ADDRESSES":   "5 6",
				"STRATEGIES_BEACONBLOCKROOT_MAJORITY_BEACON_NODE_ADDRESSES": "7 8",
			},
			expected:  []string{"1", "2"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORBEACONBLOCKROOTS",
			handler:   util.BeaconNodeAddressesForBeaconBlockRoots,
		},
		{
			name: "BeaconBlockRootFirstStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                     "1 2",
				"STRATEGIES_BEACONBLOCKROOT_STYLE":                          "first",
				"STRATEGIES_BEACONBLOCKROOT_FIRST_BEACON_NODE_ADDRESSES":    "3 4",
				"STRATEGIES_BEACONBLOCKROOT_LATEST_BEACON_NODE_ADDRESSES":   "5 6",
				"STRATEGIES_BEACONBLOCKROOT_MAJORITY_BEACON_NODE_ADDRESSES": "7 8",
			},
			expected:  []string{"3", "4"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORBEACONBLOCKROOTS",
			handler:   util.BeaconNodeAddressesForBeaconBlockRoots,
		},
		{
			name: "BeaconBlockRootLatestStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                     "1 2",
				"STRATEGIES_BEACONBLOCKROOT_STYLE":                          "latest",
				"STRATEGIES_BEACONBLOCKROOT_FIRST_BEACON_NODE_ADDRESSES":    "3 4",
				"STRATEGIES_BEACONBLOCKROOT_LATEST_BEACON_NODE_ADDRESSES":   "5 6",
				"STRATEGIES_BEACONBLOCKROOT_MAJORITY_BEACON_NODE_ADDRESSES": "7 8",
			},
			expected:  []string{"5", "6"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORBEACONBLOCKROOTS",
			handler:   util.BeaconNodeAddressesForBeaconBlockRoots,
		},
		{
			name: "BeaconBlockRootMajorityStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                     "1 2",
				"STRATEGIES_BEACONBLOCKROOT_STYLE":                          "majority",
				"STRATEGIES_BEACONBLOCKROOT_FIRST_BEACON_NODE_ADDRESSES":    "3 4",
				"STRATEGIES_BEACONBLOCKROOT_LATEST_BEACON_NODE_ADDRESSES":   "5 6",
				"STRATEGIES_BEACONBLOCKROOT_MAJORITY_BEACON_NODE_ADDRESSES": "7 8",
			},
			expected:  []string{"7", "8"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORBEACONBLOCKROOTS",
			handler:   util.BeaconNodeAddressesForBeaconBlockRoots,
		},
		{
			name: "BeaconBlockRootSimpleStrategyWithOverride",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                            "1 2",
				"STRATEGIES_BEACONBLOCKROOT_BEACON_NODE_ADDRESSES": "3 4",
			},
			expected:  []string{"3", "4"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORBEACONBLOCKROOTS",
			handler:   util.BeaconNodeAddressesForBeaconBlockRoots,
		},
		{
			name: "BeaconBlockRootDeduplication",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES": "1 2 1 3 2",
			},
			expected:  []string{"1", "2", "3"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORBEACONBLOCKROOTS",
			handler:   util.BeaconNodeAddressesForBeaconBlockRoots,
		},
		{
			name: "AttestingCombinedMajorityStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                             "1 2",
				"STRATEGIES_ATTESTATIONDATA_STYLE":                                  "combinedmajority",
				"STRATEGIES_ATTESTATIONDATA_FIRST_BEACON_NODE_ADDRESSES":            "3 4",
				"STRATEGIES_ATTESTATIONDATA_LATEST_BEACON_NODE_ADDRESSES":           "5 6",
				"STRATEGIES_ATTESTATIONDATA_MAJORITY_BEACON_NODE_ADDRESSES":         "7 8",
				"STRATEGIES_ATTESTATIONDATA_COMBINEDMAJORITY_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected:  []string{"9", "10"},
			envPrefix: "VOUCH_BEACONNODEADDRESSFORATTESTING",
			handler:   util.BeaconNodeAddressesForAttesting,
		},
	}

	templates := []struct {
		name     string
		env      map[string]string
		expected []string
	}{
		{
			name: "NoStrategy",
			env: map[string]string{
				"BEST_BEACON_NODE_ADDRESSES":  "3 4",
				"FIRST_BEACON_NODE_ADDRESSES": "5 6",
			},
			expected: []string{"1", "2"},
		},
		{
			name: "FirstStrategy",
			env: map[string]string{
				"STYLE":                       "first",
				"BEST_BEACON_NODE_ADDRESSES":  "3 4",
				"FIRST_BEACON_NODE_ADDRESSES": "5 6",
			},
			expected: []string{"5", "6"},
		},
		{
			name: "BestStrategy",
			env: map[string]string{
				"STYLE":                       "best",
				"BEST_BEACON_NODE_ADDRESSES":  "3 4",
				"FIRST_BEACON_NODE_ADDRESSES": "5 6",
			},
			expected: []string{"3", "4"},
		},
		{
			name: "SimpleStrategyWithOverride",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES": "3 4",
			},
			expected: []string{"3", "4"},
		},
		{
			name: "Deduplication",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES": "1 2 1 3 2",
			},
			expected: []string{"1", "2", "3"},
		},
	}

	strategies := []struct {
		name      string
		prefix    string
		envPrefix string
		handler   func() []string
	}{
		{
			name:      "BeaconBlockProposal",
			prefix:    "STRATEGIES_BEACONBLOCKPROPOSAL",
			envPrefix: "VOUCH_BEACONNODEADDRESSFORBEACONBLOCKPROPOSAL",
			handler:   util.BeaconNodeAddressesForBeaconBlockProposal,
		},
		{
			name:      "Attesting",
			prefix:    "STRATEGIES_ATTESTATIONDATA",
			envPrefix: "VOUCH_BEACONNODEADDRESSFORATTESTING",
			handler:   util.BeaconNodeAddressesForAttesting,
		},
		{
			name:      "AggregateAttestation",
			prefix:    "STRATEGIES_AGGREGATEATTESTATION",
			envPrefix: "VOUCH_BEACONNODEADDRESSESFORAGGREGATEATTESTATIONS",
			handler:   util.BeaconNodeAddressesForAggregateAttestations,
		},
		{
			name:      "SyncCommitteeContribution",
			prefix:    "STRATEGIES_SYNCCOMMITTEECONTRIBUTION",
			envPrefix: "VOUCH_BEACONNODEADDRESSFORSYNCCOMMITTEECONTRIBUTIONS",
			handler:   util.BeaconNodeAddressesForSyncCommitteeContributions,
		},
	}

	for _, strategy := range strategies {
		for _, template := range templates {
			env := make(map[string]string)
			for k, v := range template.env {
				env[fmt.Sprintf("%s_%s", strategy.prefix, k)] = v
			}
			env["BEACON_NODE_ADDRESSES"] = "1 2"

			tests = append(tests, struct {
				name      string
				env       map[string]string
				expected  []string
				envPrefix string
				handler   func() []string
			}{
				name:      fmt.Sprintf("%s%s", strategy.name, template.name),
				env:       env,
				expected:  template.expected,
				envPrefix: strategy.envPrefix,
				handler:   strategy.handler,
			})
		}
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := fmt.Sprintf("%s_%s", strings.ToUpper(test.envPrefix), strings.ToUpper(test.name))
			for k, v := range test.env {
				os.Setenv(fmt.Sprintf("%s_%s", prefix, k), v)
			}
			viper.SetEnvPrefix(prefix)
			res := test.handler()
			sort.Strings(test.expected)
			sort.Strings(res)
			require.Equal(t, test.expected, res)
		})
	}
}
