// Copyright © 2024 - 2026 Attestant Limited.
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
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestAttestationDataThreshold(t *testing.T) {
	tests := []struct {
		name     string
		majority any
		combined any
		want     int
	}{
		{
			name:     "inherits documented majority threshold",
			majority: 2,
			want:     2,
		},
		{
			name:     "strategy-specific threshold overrides shared threshold",
			majority: 2,
			combined: 3,
			want:     3,
		},
		{
			name:     "explicit zero override is preserved",
			majority: 2,
			combined: 0,
			want:     0,
		},
		{
			name: "unset thresholds retain zero default",
			want: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			if test.majority != nil {
				viper.Set("strategies.attestationdata.majority.threshold", test.majority)
			}
			if test.combined != nil {
				viper.Set("strategies.attestationdata.combinedmajority.threshold", test.combined)
			}

			require.Equal(t, test.want, util.AttestationDataThreshold())
		})
	}
}
