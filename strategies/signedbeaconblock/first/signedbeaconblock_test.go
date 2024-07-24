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

package first_test

import (
	"context"
	"testing"
	"time"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/strategies/signedbeaconblock/first"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSignedBeaconBlock(t *testing.T) {
	tests := []struct {
		name            string
		params          []first.Parameter
		blockID         string
		beaconBlockRoot phase0.Root
		err             string
	}{
		{
			name: "Good",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithSignedBeaconBlockProviders(map[string]consensusclient.SignedBeaconBlockProvider{
					"good": mock.NewSignedBeaconBlockProvider(),
				}),
			},
			blockID: "1",
			beaconBlockRoot: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
		{
			name: "Timeout",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(time.Second),
				first.WithSignedBeaconBlockProviders(map[string]consensusclient.SignedBeaconBlockProvider{
					"sleepy": mock.NewSleepySignedBeaconBlockProvider(5*time.Second, mock.NewSignedBeaconBlockProvider()),
				}),
			},
			blockID: "1",
			beaconBlockRoot: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
			err: "failed to obtain beacon block header before timeout",
		},
		{
			name: "GoodMixed",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithSignedBeaconBlockProviders(map[string]consensusclient.SignedBeaconBlockProvider{
					"error":  mock.NewErroringSignedBeaconBlockProvider(),
					"sleepy": mock.NewSleepySignedBeaconBlockProvider(time.Second, mock.NewSignedBeaconBlockProvider()),
				}),
			},
			blockID: "1",
			beaconBlockRoot: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
	}

	for _, test := range tests {
		s, err := first.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			root, err := s.SignedBeaconBlock(context.Background(), &api.SignedBeaconBlockOpts{
				Block: test.blockID,
			})
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, root)
			}
		})
	}
}
