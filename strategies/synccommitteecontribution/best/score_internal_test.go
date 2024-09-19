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

package best

import (
	"context"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/vouch/mock"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// populatedBitvector creates a populated bitlist.
func populatedBitvector(set uint64) bitfield.Bitvector128 {
	res := bitfield.NewBitvector128()
	for i := uint64(0); i < set; i++ {
		res.SetBitAt(i, true)
	}

	return res
}

func TestScore(t *testing.T) {
	ctx := context.Background()

	s, err := New(ctx,
		WithLogLevel(zerolog.Disabled),
		WithTimeout(2*time.Second),
		WithSyncCommitteeContributionProviders(map[string]eth2client.SyncCommitteeContributionProvider{
			"good": mock.NewSyncCommitteeContributionProvider(),
		}),
	)
	require.NoError(t, err)

	tests := []struct {
		name         string
		contribution *altair.SyncCommitteeContribution
		score        float64
	}{
		{
			name:  "Nil",
			score: 0,
		},
		{
			name: "Empty",
			contribution: &altair.SyncCommitteeContribution{
				Slot:              1,
				SubcommitteeIndex: 2,
				AggregationBits:   populatedBitvector(0),
			},
			score: 0,
		},
		{
			name: "Full",
			contribution: &altair.SyncCommitteeContribution{
				Slot:              1,
				SubcommitteeIndex: 2,
				AggregationBits:   populatedBitvector(128),
			},
			score: 128,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			score := s.scoreSyncCommitteeContribution(ctx, "test", test.contribution)
			require.Equal(t, test.score, score)
		})
	}
}
