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
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/strategies/beaconblockheader/first"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	providers := map[string]consensusclient.BeaconBlockHeadersProvider{
		"localhost:1": mock.NewBeaconBlockHeadersProvider(),
	}

	tests := []struct {
		name   string
		params []first.Parameter
		err    string
	}{
		{
			name: "TimeoutMissing",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.TraceLevel),
				first.WithBeaconBlockHeadersProviders(providers),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "TimeoutZero",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.TraceLevel),
				first.WithTimeout(0),
				first.WithBeaconBlockHeadersProviders(providers),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "ProvidersNil",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.TraceLevel),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(nil),
			},
			err: "problem with parameters: no beacon block headers providers specified",
		},
		{
			name: "ProvidersEmpty",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.TraceLevel),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(map[string]consensusclient.BeaconBlockHeadersProvider{}),
			},
			err: "problem with parameters: no beacon block headers providers specified",
		},
		{
			name: "Good",
			params: []first.Parameter{
				first.WithLogLevel(zerolog.TraceLevel),
				first.WithTimeout(2 * time.Second),
				first.WithBeaconBlockHeadersProviders(providers),
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
	providers := map[string]consensusclient.BeaconBlockHeadersProvider{
		"localhost:1": mock.NewBeaconBlockHeadersProvider(),
	}

	s, err := first.New(context.Background(),
		first.WithLogLevel(zerolog.Disabled),
		first.WithTimeout(2*time.Second),
		first.WithBeaconBlockHeadersProviders(providers),
	)
	require.NoError(t, err)
	require.Implements(t, (*consensusclient.BeaconBlockHeadersProvider)(nil), s)
}
