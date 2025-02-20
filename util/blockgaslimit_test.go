// Copyright © 2025 Attestant Limited.
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
	"testing"

	"github.com/attestantio/vouch/util"
	"github.com/stretchr/testify/require"
)

func TestExpectedGasLimit(t *testing.T) {
	tests := []struct {
		name     string
		latest   uint64
		target   uint64
		expected uint64
	}{
		{
			name:     "Zero",
			latest:   0,
			target:   0,
			expected: 0,
		},
		{
			name:     "FarBelow",
			latest:   1000000,
			target:   2000000,
			expected: 1000975,
		},
		{
			name:     "NearBelow",
			latest:   1999990,
			target:   2000000,
			expected: 2000000,
		},
		{
			name:     "FarAbove",
			latest:   2000000,
			target:   1000000,
			expected: 1998048,
		},
		{
			name:     "NearAbove",
			latest:   2000000,
			target:   1999990,
			expected: 1999990,
		},
		{
			name:     "Equal",
			latest:   2000000,
			target:   2000000,
			expected: 2000000,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, util.ExpectedGasLimit(test.latest, test.target))
		})
	}
}
