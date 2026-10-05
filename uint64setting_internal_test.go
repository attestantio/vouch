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
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestUint64Setting(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		expected uint64
		err      string
	}{
		{name: "Unset", yaml: "other: 1", expected: 0},
		{name: "Integer", yaml: "key: 90", expected: 90},
		{name: "Zero", yaml: "key: 0", expected: 0},
		{name: "IntegerString", yaml: `key: "90"`, expected: 90},
		{name: "Negative", yaml: "key: -1", err: "key: invalid value -1; must be a non-negative integer"},
		{name: "Typo", yaml: `key: "9O"`, err: "key: invalid value 9O; must be a non-negative integer"},
		{name: "Percent", yaml: `key: "90%"`, err: "key: invalid value 90%; must be a non-negative integer"},
		{name: "Fraction", yaml: "key: 0.01", err: "key: invalid value 0.01; must be a non-negative integer"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			viper.Reset()
			defer viper.Reset()
			viper.SetConfigType("yaml")
			require.NoError(t, viper.ReadConfig(strings.NewReader(test.yaml)))

			value, err := uint64Setting("key")
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expected, value)
			}
		})
	}
}
