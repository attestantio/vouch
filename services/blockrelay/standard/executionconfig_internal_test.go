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

package standard

import (
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

func TestPubKeysToArray(t *testing.T) {
	tests := []struct {
		name     string
		pubkeys  []phase0.BLSPubKey
		expected string
	}{
		{
			name:     "None",
			pubkeys:  []phase0.BLSPubKey{},
			expected: `[]`,
		},
		{
			name: "One",
			pubkeys: []phase0.BLSPubKey{
				{0x01},
			},
			expected: `["0x010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]`,
		},
		{
			name: "Two",
			pubkeys: []phase0.BLSPubKey{
				{0x01}, {0x02},
			},
			expected: `["0x010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","0x020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]`,
		},
		{
			name: "Three",
			pubkeys: []phase0.BLSPubKey{
				{0x01}, {0x02}, {0x03},
			},
			expected: `["0x010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","0x020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","0x030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := pubKeysToArray(test.pubkeys)
			require.Equal(t, test.expected, res)
		})
	}
}
