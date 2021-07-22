// Copyright © 2021 Attestant Limited.
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

func TestProcessConcurrency(t *testing.T) {

	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	tests := []struct {
		name     string
		path     string
		env      map[string]string
		expected int64
	}{
		{
			name: "Empty",
			env: map[string]string{
				"PROCESS_CONCURRENCY": "12345",
			},
			expected: 12345,
		},
		{
			name: "MultilevelRoot",
			env: map[string]string{
				"PROCESS_CONCURRENCY": "12345",
			},
			path:     "a.b.c.process-concurrency",
			expected: 12345,
		},
		{
			name: "MultilevelBranch",
			env: map[string]string{
				"PROCESS_CONCURRENCY":     "12345",
				"A_B_PROCESS_CONCURRENCY": "54321",
			},
			path:     "a.b.c.process-concurrency",
			expected: 54321,
		},
		{
			name: "Unknown",
			env: map[string]string{
				"FOO": "12345",
			},
			path:     "process-concurrency",
			expected: 0,
		},
		{
			name: "Fallback",
			env: map[string]string{
				"PROCESS_CONCURRENCY": "12345",
			},
			path:     "foo",
			expected: 12345,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := fmt.Sprintf("VOUCH_%s", strings.ToUpper(test.name))
			for k, v := range test.env {
				os.Setenv(fmt.Sprintf("%s_%s", prefix, k), v)
			}
			viper.SetEnvPrefix(prefix)
			res := util.ProcessConcurrency(test.path)
			require.Equal(t, test.expected, res)
		})
	}
}
