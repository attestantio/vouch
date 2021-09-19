// Copyright © 2020, 2021 Attestant Limited.
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
	"github.com/attestantio/vouch/strategies/aggregateattestation/best"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	aggregateAttestationProviders := map[string]eth2client.AggregateAttestationProvider{
		"localhost:1": mock.NewAggregateAttestationProvider(),
	}

	tests := []struct {
		name   string
		params []best.Parameter
		err    string
	}{
		{
			name: "TimeoutMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithAggregateAttestationProviders(aggregateAttestationProviders),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "TimeoutZero",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(0),
				best.WithAggregateAttestationProviders(aggregateAttestationProviders),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "ClientMonitorMissing",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(2 * time.Second),
				best.WithClientMonitor(nil),
				best.WithAggregateAttestationProviders(aggregateAttestationProviders),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "AggregateAttestationProvidersNil",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(2 * time.Second),
				best.WithAggregateAttestationProviders(nil),
			},
			err: "problem with parameters: no aggregate attestation providers specified",
		},
		{
			name: "ProcessConcurrencyZero",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(2 * time.Second),
				best.WithAggregateAttestationProviders(aggregateAttestationProviders),
				best.WithProcessConcurrency(0),
			},
			err: "problem with parameters: no process concurrency specified",
		},
		{
			name: "AggregateAttestationProvidersEmpty",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(2 * time.Second),
				best.WithAggregateAttestationProviders(map[string]eth2client.AggregateAttestationProvider{}),
			},
			err: "problem with parameters: no aggregate attestation providers specified",
		},
		{
			name: "Good",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(2 * time.Second),
				best.WithAggregateAttestationProviders(aggregateAttestationProviders),
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
	aggregateAttestationProviders := map[string]eth2client.AggregateAttestationProvider{
		"localhost:1": mock.NewAggregateAttestationProvider(),
	}

	s, err := best.New(context.Background(),
		best.WithLogLevel(zerolog.Disabled),
		best.WithTimeout(2*time.Second),
		best.WithAggregateAttestationProviders(aggregateAttestationProviders),
	)
	require.NoError(t, err)
	require.Implements(t, (*eth2client.AggregateAttestationProvider)(nil), s)
}
