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
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/strategies/synccommitteecontribution/best"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	syncCommitteeContributionProviders := map[string]eth2client.SyncCommitteeContributionProvider{
		"localhost:1": mock.NewSyncCommitteeContributionProvider(),
	}

	tests := []struct {
		name   string
		params []best.Parameter
		err    string
	}{
		{
			name: "TimeoutMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithSyncCommitteeContributionProviders(syncCommitteeContributionProviders),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "TimeoutZero",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(0),
				best.WithSyncCommitteeContributionProviders(syncCommitteeContributionProviders),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "SyncCommitteeContributionProvidersNil",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithSyncCommitteeContributionProviders(nil),
			},
			err: "problem with parameters: no sync committee contribution providers specified",
		},
		{
			name: "ProcessConcurrencyZero",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithSyncCommitteeContributionProviders(syncCommitteeContributionProviders),
				best.WithProcessConcurrency(0),
			},
			err: "problem with parameters: no process concurrency specified",
		},
		{
			name: "SyncCommitteeContributionProvidersEmpty",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithSyncCommitteeContributionProviders(map[string]eth2client.SyncCommitteeContributionProvider{}),
			},
			err: "problem with parameters: no sync committee contribution providers specified",
		},
		{
			name: "Good",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.Disabled),
				best.WithTimeout(2 * time.Second),
				best.WithSyncCommitteeContributionProviders(syncCommitteeContributionProviders),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := best.New(context.Background(), test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestInterfaces(t *testing.T) {
	syncCommitteeContributionProviders := map[string]eth2client.SyncCommitteeContributionProvider{
		"localhost:1": mock.NewSyncCommitteeContributionProvider(),
	}

	s, err := best.New(context.Background(),
		best.WithLogLevel(zerolog.Disabled),
		best.WithTimeout(2*time.Second),
		best.WithSyncCommitteeContributionProviders(syncCommitteeContributionProviders),
	)
	require.NoError(t, err)
	require.Implements(t, (*eth2client.SyncCommitteeContributionProvider)(nil), s)
}
