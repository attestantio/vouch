// Copyright © 2021, 2023 Attestant Limited.
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

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/strategies/synccommitteecontribution/first"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSyncCommitteeContribution(t *testing.T) {
	tests := []struct {
		name   string
		params []first.Parameter
		opts   *api.SyncCommitteeContributionOpts
		err    string
	}{
		{
			name: "NilOpts",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithSyncCommitteeContributionProviders(map[string]eth2client.SyncCommitteeContributionProvider{
					"good": mock.NewSyncCommitteeContributionProvider(),
				}),
			},
			err: "no options specified",
		},
		{
			name: "Good",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithSyncCommitteeContributionProviders(map[string]eth2client.SyncCommitteeContributionProvider{
					"good": mock.NewSyncCommitteeContributionProvider(),
				}),
			},
			opts: &api.SyncCommitteeContributionOpts{
				Slot:              12345,
				SubcommitteeIndex: 1,
				BeaconBlockRoot: phase0.Root{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
			},
		},
		{
			name: "Timeout",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(time.Second),
				first.WithSyncCommitteeContributionProviders(map[string]eth2client.SyncCommitteeContributionProvider{
					"sleepy": mock.NewSleepySyncCommitteeContributionProvider(5*time.Second, mock.NewSyncCommitteeContributionProvider()),
				}),
			},
			opts: &api.SyncCommitteeContributionOpts{
				Slot:              12345,
				SubcommitteeIndex: 1,
				BeaconBlockRoot: phase0.Root{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
			},
			err: "failed to obtain sync committee contribution before timeout",
		},
		{
			name: "GoodMixed",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2 * time.Second),
				first.WithSyncCommitteeContributionProviders(map[string]eth2client.SyncCommitteeContributionProvider{
					"error":  mock.NewErroringSyncCommitteeContributionProvider(),
					"sleepy": mock.NewSleepySyncCommitteeContributionProvider(time.Second, mock.NewSyncCommitteeContributionProvider()),
				}),
			},
			opts: &api.SyncCommitteeContributionOpts{
				Slot:              12345,
				SubcommitteeIndex: 1,
				BeaconBlockRoot: phase0.Root{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
			},
		},
	}

	for _, test := range tests {
		s, err := first.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			contribution, err := s.SyncCommitteeContribution(context.Background(), test.opts)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, contribution)
			}
		})
	}
}
