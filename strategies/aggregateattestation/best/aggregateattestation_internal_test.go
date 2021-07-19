// Copyright © 2020 Attestant Limited.
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

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// populatedBitlist creates a populated bitlist.
func populatedBitlist(size uint64, set uint64) bitfield.Bitlist {
	res := bitfield.NewBitlist(size)
	for i := uint64(0); i < set; i++ {
		res.SetBitAt(i, true)
	}

	return res
}

func TestScore(t *testing.T) {
	ctx := context.Background()

	s, err := New(ctx,
		WithLogLevel(zerolog.Disabled),
		WithAggregateAttestationProviders(map[string]eth2client.AggregateAttestationProvider{
			"good": mock.NewAggregateAttestationProvider(),
		}),
	)
	require.NoError(t, err)

	tests := []struct {
		name      string
		aggregate *phase0.Attestation
		score     float64
	}{
		{
			name:  "Nil",
			score: 0,
		},
		{
			name: "Empty",
			aggregate: &phase0.Attestation{
				AggregationBits: populatedBitlist(100, 0),
				Data: &phase0.AttestationData{
					Slot: 5,
				},
			},
			score: 0,
		},
		{
			name: "Full",
			aggregate: &phase0.Attestation{
				AggregationBits: populatedBitlist(100, 100),
				Data: &phase0.AttestationData{
					Slot: 5,
				},
			},
			score: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			score := s.scoreAggregateAttestation(ctx, "test", test.aggregate)
			require.Equal(t, test.score, score)
		})
	}
}
