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
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/attestantio/vouch/util"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestBeaconNodeAddresses(t *testing.T) {
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	tests := []struct {
		name     string
		path     string
		env      map[string]string
		expected []string
	}{
		{
			name: "Empty",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES": "1 2",
			},
			expected: []string{"1", "2"},
		},
		{
			name: "MultilevelRoot",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES": "1 2",
			},
			path:     "a.b.c",
			expected: []string{"1", "2"},
		},
		{
			name: "TrailingDot",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":     "1 2",
				"A_B_BEACON_NODE_ADDRESSES": "3 4",
			},
			path:     "a.b.c.",
			expected: []string{"3", "4"},
		},
		{
			name: "MultilevelBranch",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES":     "1 2",
				"A_B_BEACON_NODE_ADDRESSES": "3 4",
			},
			path:     "a.b.c",
			expected: []string{"3", "4"},
		},
		{
			name: "Unknown",
			env: map[string]string{
				"FOO": "1 2",
			},
			path:     "beacon-node-addresses",
			expected: nil,
		},
		{
			name: "Fallback",
			env: map[string]string{
				"BEACON_NODE_ADDRESSES": "1 2",
			},
			path:     "foo",
			expected: []string{"1", "2"},
		},
		{
			name: "SingleAddress",
			env: map[string]string{
				"BEACON_NODE_ADDRESS": "1",
			},
			path:     "foo",
			expected: []string{"1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := fmt.Sprintf("VOUCH_%s", strings.ToUpper(test.name))
			for k, v := range test.env {
				os.Setenv(fmt.Sprintf("%s_%s", prefix, k), v)
			}
			viper.SetEnvPrefix(prefix)
			res := util.BeaconNodeAddresses(test.path)
			require.Equal(t, test.expected, res)
		})
	}
}
