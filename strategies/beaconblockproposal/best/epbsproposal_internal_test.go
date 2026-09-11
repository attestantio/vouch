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

package best

import (
	"math/big"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestConsiderEPBSProposalUnknownValues(t *testing.T) {
	tests := []struct {
		name     string
		values   []*big.Int
		expected int
	}{
		{
			name:     "KnownPositiveLater",
			values:   []*big.Int{nil, big.NewInt(1)},
			expected: 1,
		},
		{
			name:     "KnownZeroLater",
			values:   []*big.Int{nil, big.NewInt(0)},
			expected: 1,
		},
		{
			name:     "KnownZeroFirst",
			values:   []*big.Int{big.NewInt(0), nil},
			expected: 0,
		},
		{
			name:     "AllUnknown",
			values:   []*big.Int{nil, nil},
			expected: 0,
		},
		{
			name:     "EqualKnownValues",
			values:   []*big.Int{big.NewInt(1), big.NewInt(1)},
			expected: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &Service{}
			var selected *api.VersionedEPBSProposal
			var selectedProvider string
			proposals := make([]*api.VersionedEPBSProposal, len(test.values))
			for index, value := range test.values {
				proposals[index] = &api.VersionedEPBSProposal{ExecutionValue: value}
				selected, selectedProvider = service.considerEPBSProposal(
					&api.EPBSProposalOpts{},
					&beaconBlockEPBSResponse{provider: "provider", proposal: proposals[index]},
					selected,
					selectedProvider,
					zerolog.Nop(),
				)
			}
			require.Same(t, proposals[test.expected], selected)
		})
	}
}
