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

package best_test

import (
	"context"
	"testing"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/strategies/beaconblockproposal/best"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestBeaconBlockProposal(t *testing.T) {
	ctx := context.Background()

	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(null.New(context.Background())),
		best.WithProcessConcurrency(6),
		best.WithBeaconBlockProposalProviders(map[string]eth2client.BeaconBlockProposalProvider{
			"one":   mock.NewBeaconBlockProposalProvider(),
			"two":   mock.NewBeaconBlockProposalProvider(),
			"three": mock.NewBeaconBlockProposalProvider(),
		}),
	)
	require.NoError(t, err)

	block, err := service.BeaconBlockProposal(ctx,
		12345,
		[]byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, block)

	//	for _, test := range tests {
	//		t.Run(test.name, func(t *testing.T) {
	//			_, err := best.New(context.Background(), test.params...)
	//			if test.err != "" {
	//				require.EqualError(t, err, test.err)
	//			} else {
	//				require.NoError(t, err)
	//			}
	//		})
	//	}
}
