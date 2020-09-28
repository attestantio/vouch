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

package null_test

import (
	"context"
	"testing"

	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/services/submitter/null"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	tests := []struct {
		name   string
		params []null.Parameter
	}{
		{
			name: "Good",
			params: []null.Parameter{
				null.WithLogLevel(zerolog.Disabled),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := null.New(context.Background(), test.params...)
			require.NoError(t, err)
		})
	}
}

func TestSubmit(t *testing.T) {
	s, err := null.New(context.Background(),
		null.WithLogLevel(zerolog.Disabled),
	)
	require.NoError(t, err)

	require.EqualError(t, s.SubmitBeaconBlock(context.Background(), nil), "no beacon block supplied")
	require.EqualError(t, s.SubmitAttestation(context.Background(), nil), "no attestation supplied")
	require.EqualError(t, s.SubmitBeaconCommitteeSubscriptions(context.Background(), nil), "no subscriptions supplied")
	require.EqualError(t, s.SubmitAggregateAttestation(context.Background(), nil), "no aggregate attestation supplied")
}

func TestInterfaces(t *testing.T) {
	s, err := null.New(context.Background(),
		null.WithLogLevel(zerolog.Disabled),
	)
	require.NoError(t, err)
	require.Implements(t, (*submitter.BeaconBlockSubmitter)(nil), s)
	require.Implements(t, (*submitter.AttestationSubmitter)(nil), s)
	require.Implements(t, (*submitter.BeaconCommitteeSubscriptionsSubmitter)(nil), s)
	require.Implements(t, (*submitter.AggregateAttestationSubmitter)(nil), s)
}
