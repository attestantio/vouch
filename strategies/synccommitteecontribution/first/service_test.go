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

package first_test

import (
	"context"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/strategies/synccommitteecontribution/first"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	syncCommitteeContributionProviders := map[string]eth2client.SyncCommitteeContributionProvider{
		"localhost:1": mock.NewSyncCommitteeContributionProvider(),
	}

	tests := []struct {
		name   string
		params []first.Parameter
		err    string
	}{
		{
			name: "TimeoutZero",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.TraceLevel),
				first.WithTimeout(0),
				first.WithSyncCommitteeContributionProviders(syncCommitteeContributionProviders),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "ClientMonitorMissing",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.TraceLevel),
				first.WithClientMonitor(nil),
				first.WithSyncCommitteeContributionProviders(syncCommitteeContributionProviders),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "SyncCommitteeContributionProvidersNil",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.TraceLevel),
				first.WithSyncCommitteeContributionProviders(nil),
			},
			err: "problem with parameters: no sync committee contribution providers specified",
		},
		{
			name: "SyncCommitteeContributionProvidersEmpty",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.TraceLevel),
				first.WithSyncCommitteeContributionProviders(map[string]eth2client.SyncCommitteeContributionProvider{}),
			},
			err: "problem with parameters: no sync committee contribution providers specified",
		},
		{
			name: "Good",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.TraceLevel),
				first.WithTimeout(10 * time.Second),
				first.WithSyncCommitteeContributionProviders(syncCommitteeContributionProviders),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := first.New(context.Background(), test.params...)
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

	s, err := first.New(context.Background(),
		first.WithLogLevel(zerolog.Disabled),
		first.WithSyncCommitteeContributionProviders(syncCommitteeContributionProviders),
	)
	require.NoError(t, err)
	require.Implements(t, (*eth2client.SyncCommitteeContributionProvider)(nil), s)
}
