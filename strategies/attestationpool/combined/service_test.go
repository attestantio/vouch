// Copyright © 2025 Attestant Limited.
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

package combined_test

import (
	"context"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/strategies/attestationpool/combined"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	ctx := context.Background()

	attestationPoolProviders := map[string]eth2client.AttestationPoolProvider{
		"localhost:1": mock.NewAttestationPoolProvider(),
	}

	tests := []struct {
		name   string
		params []combined.Parameter
		err    string
	}{
		{
			name: "TimeoutMissing",
			params: []combined.Parameter{
				combined.WithLogLevel(zerolog.TraceLevel),
				combined.WithAttestationPoolProviders(attestationPoolProviders),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "TimeoutZero",
			params: []combined.Parameter{
				combined.WithLogLevel(zerolog.TraceLevel),
				combined.WithTimeout(0),
				combined.WithAttestationPoolProviders(attestationPoolProviders),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "ClientMonitorMissing",
			params: []combined.Parameter{
				combined.WithLogLevel(zerolog.TraceLevel),
				combined.WithTimeout(2 * time.Second),
				combined.WithClientMonitor(nil),
				combined.WithAttestationPoolProviders(attestationPoolProviders),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "AttestationPoolProvidersNil",
			params: []combined.Parameter{
				combined.WithLogLevel(zerolog.TraceLevel),
				combined.WithTimeout(2 * time.Second),
				combined.WithAttestationPoolProviders(nil),
			},
			err: "problem with parameters: no attestation pool providers specified",
		},
		{
			name: "AttestationDataProvidersEmpty",
			params: []combined.Parameter{
				combined.WithLogLevel(zerolog.TraceLevel),
				combined.WithTimeout(2 * time.Second),
				combined.WithAttestationPoolProviders(map[string]eth2client.AttestationPoolProvider{}),
			},
			err: "problem with parameters: no attestation pool providers specified",
		},
		{
			name: "Good",
			params: []combined.Parameter{
				combined.WithLogLevel(zerolog.TraceLevel),
				combined.WithTimeout(2 * time.Second),
				combined.WithAttestationPoolProviders(attestationPoolProviders),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := combined.New(ctx, test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
