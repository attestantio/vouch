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

func TestBeaconNodeAddressesForProposing(t *testing.T) {
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	tests := []struct {
		name     string
		env      map[string]string
		expected []string
	}{
		{
			name: "NoStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES": "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":         "3 4",
				"STRATEGIES_BEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES":        "5 6",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":  "7 8",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected: []string{"1", "2"},
		},
		{
			name: "FirstStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                             "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_STYLE":                              "first",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":         "3 4",
				"STRATEGIES_BEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES":        "5 6",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":  "7 8",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected: []string{"1", "2", "5", "6"},
		},
		{
			name: "FirstStrategies",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                             "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_STYLE":                              "first",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":         "3 4",
				"STRATEGIES_BEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES":        "5 6",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_STYLE":                       "first",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":  "7 8",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected: []string{"5", "6", "9", "10"},
		},
		{
			name: "BestStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                             "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_STYLE":                              "best",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":         "3 4",
				"STRATEGIES_BEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES":        "5 6",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":  "7 8",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected: []string{"1", "2", "3", "4"},
		},
		{
			name: "BestStrategies",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                             "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_STYLE":                              "best",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":         "3 4",
				"STRATEGIES_BEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES":        "5 6",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_STYLE":                       "best",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":  "7 8",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected: []string{"3", "4", "7", "8"},
		},
		{
			name: "MixedStrategies",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                             "1 2",
				"STRATEGIES_BEACONBLOCKPROPOSAL_STYLE":                              "best",
				"STRATEGIES_BEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":         "3 4",
				"STRATEGIES_BEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES":        "5 6",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_STYLE":                       "first",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_BEST_BEACON_NODE_ADDRESSES":  "7 8",
				"STRATEGIES_BLINDEDBEACONBLOCKPROPOSAL_FIRST_BEACON_NODE_ADDRESSES": "9 10",
			},
			expected: []string{"3", "4", "9", "10"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := fmt.Sprintf("VOUCH_BEACONNODEADDRESSFORPROPOSING_%s", strings.ToUpper(test.name))
			for k, v := range test.env {
				os.Setenv(fmt.Sprintf("%s_%s", prefix, k), v)
			}
			viper.SetEnvPrefix(prefix)
			res := util.BeaconNodeAddressesForProposing()
			sort.Strings(test.expected)
			sort.Strings(res)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestBeaconNodeAddressesForAttesting(t *testing.T) {
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	tests := []struct {
		name     string
		env      map[string]string
		expected []string
	}{
		{
			name: "NoStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                     "1 2",
				"STRATEGIES_ATTESTATIONDATA_BEST_BEACON_NODE_ADDRESSES":     "3 4",
				"STRATEGIES_ATTESTATIONDATA_FIRST_BEACON_NODE_ADDRESSES":    "5 6",
				"STRATEGIES_ATTESTATIONDATA_MAJORITY_BEACON_NODE_ADDRESSES": "7 8",
			},
			expected: []string{"1", "2"},
		},
		{
			name: "FirstStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                     "1 2",
				"STRATEGIES_ATTESTATIONDATA_STYLE":                          "first",
				"STRATEGIES_ATTESTATIONDATA_BEST_BEACON_NODE_ADDRESSES":     "3 4",
				"STRATEGIES_ATTESTATIONDATA_FIRST_BEACON_NODE_ADDRESSES":    "5 6",
				"STRATEGIES_ATTESTATIONDATA_MAJORITY_BEACON_NODE_ADDRESSES": "7 8",
			},
			expected: []string{"5", "6"},
		},
		{
			name: "BestStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                     "1 2",
				"STRATEGIES_ATTESTATIONDATA_STYLE":                          "best",
				"STRATEGIES_ATTESTATIONDATA_BEST_BEACON_NODE_ADDRESSES":     "3 4",
				"STRATEGIES_ATTESTATIONDATA_FIRST_BEACON_NODE_ADDRESSES":    "5 6",
				"STRATEGIES_ATTESTATIONDATA_MAJORITY_BEACON_NODE_ADDRESSES": "7 8",
			},
			expected: []string{"3", "4"},
		},
		{
			name: "MajorityStrategy",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":                                     "1 2",
				"STRATEGIES_ATTESTATIONDATA_STYLE":                          "majority",
				"STRATEGIES_ATTESTATIONDATA_BEST_BEACON_NODE_ADDRESSES":     "3 4",
				"STRATEGIES_ATTESTATIONDATA_FIRST_BEACON_NODE_ADDRESSES":    "5 6",
				"STRATEGIES_ATTESTATIONDATA_MAJORITY_BEACON_NODE_ADDRESSES": "7 8",
			},
			expected: []string{"7", "8"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := fmt.Sprintf("VOUCH_BEACONNODEADDRESSFORATTESTING_%s", strings.ToUpper(test.name))
			for k, v := range test.env {
				os.Setenv(fmt.Sprintf("%s_%s", prefix, k), v)
			}
			viper.SetEnvPrefix(prefix)
			res := util.BeaconNodeAddressesForAttesting()
			sort.Strings(test.expected)
			sort.Strings(res)
			require.Equal(t, test.expected, res)
		})
	}
}
