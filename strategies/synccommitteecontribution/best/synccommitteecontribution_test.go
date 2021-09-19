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

package best_test

import (
	"context"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/strategies/synccommitteecontribution/best"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSyncCommitteeContribution(t *testing.T) {
	tests := []struct {
		name              string
		params            []best.Parameter
		slot              phase0.Slot
		subcommitteeIndex uint64
		beaconBlockRoot   phase0.Root
		err               string
	}{
		{
			name: "Good",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithSyncCommitteeContributionProviders(map[string]eth2client.SyncCommitteeContributionProvider{
					"good": mock.NewSyncCommitteeContributionProvider(),
				}),
			},
			slot:              12345,
			subcommitteeIndex: 1,
			beaconBlockRoot: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
		{
			name: "Timeout",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(time.Second),
				best.WithSyncCommitteeContributionProviders(map[string]eth2client.SyncCommitteeContributionProvider{
					"sleepy": mock.NewSleepySyncCommitteeContributionProvider(5*time.Second, mock.NewSyncCommitteeContributionProvider()),
				}),
			},
			slot:              12345,
			subcommitteeIndex: 1,
			beaconBlockRoot: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
			err: "no sync committee contribution received",
		},
		{
			name: "NilResponse",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(time.Second),
				best.WithSyncCommitteeContributionProviders(map[string]eth2client.SyncCommitteeContributionProvider{
					"nil": mock.NewNilSyncCommitteeContributionProvider(),
				}),
			},
			slot:              12345,
			subcommitteeIndex: 1,
			beaconBlockRoot: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
			err: "no sync committee contribution received",
		},
		{
			name: "GoodMixed",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithSyncCommitteeContributionProviders(map[string]eth2client.SyncCommitteeContributionProvider{
					"error":  mock.NewErroringSyncCommitteeContributionProvider(),
					"sleepy": mock.NewSleepySyncCommitteeContributionProvider(time.Second, mock.NewSyncCommitteeContributionProvider()),
				}),
			},
			slot:              12345,
			subcommitteeIndex: 1,
			beaconBlockRoot: phase0.Root{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
	}

	for _, test := range tests {
		s, err := best.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			contribution, err := s.SyncCommitteeContribution(context.Background(), test.slot, test.subcommitteeIndex, test.beaconBlockRoot)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, contribution)
			}
		})
	}
}
