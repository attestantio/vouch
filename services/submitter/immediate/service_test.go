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

package immediate_test

import (
	"context"
	"testing"

	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/services/submitter/immediate"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	attestationSubmitter := mock.NewAttestationSubmitter()
	beaconBlockSubmitter := mock.NewBeaconBlockSubmitter()
	beaconCommitteeSubscriptionSubmitter := mock.NewBeaconCommitteeSubscriptionsSubmitter()
	aggregateAttestationSubmitter := mock.NewAggregateAttestationsSubmitter()

	tests := []struct {
		name   string
		params []immediate.Parameter
		err    string
	}{
		{
			name: "AttestationSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithBeaconBlockSubmitter(beaconBlockSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
			},
			err: "problem with parameters: no attestation submitter specified",
		},
		{
			name: "BeaconBlockSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(attestationSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
			},
			err: "problem with parameters: no beacon block submitter specified",
		},
		{
			name: "AttestationSubnetSubscriptionsSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(attestationSubmitter),
				immediate.WithBeaconBlockSubmitter(beaconBlockSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
			},
			err: "problem with parameters: no beacon committee subscriptions submitter specified",
		},
		{
			name: "AggregateAttestationSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(attestationSubmitter),
				immediate.WithBeaconBlockSubmitter(beaconBlockSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
			},
			err: "problem with parameters: no aggregate attestations submitter specified",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(attestationSubmitter),
				immediate.WithBeaconBlockSubmitter(beaconBlockSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := immediate.New(context.Background(), test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSubmit(t *testing.T) {
	s, err := immediate.New(context.Background(),
		immediate.WithLogLevel(zerolog.Disabled),
		immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
		immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
		immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
		immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
	)
	require.NoError(t, err)

	require.EqualError(t, s.SubmitBeaconBlock(context.Background(), nil), "no beacon block supplied")
	require.EqualError(t, s.SubmitAttestation(context.Background(), nil), "no attestation supplied")
	require.EqualError(t, s.SubmitBeaconCommitteeSubscriptions(context.Background(), nil), "no subscriptions supplied")
	require.EqualError(t, s.SubmitAggregateAttestation(context.Background(), nil), "no aggregate attestation supplied")
}

func TestInterfaces(t *testing.T) {
	s, err := immediate.New(context.Background(),
		immediate.WithLogLevel(zerolog.Disabled),
		immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
		immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
		immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
		immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
	)
	require.NoError(t, err)
	require.Implements(t, (*submitter.BeaconBlockSubmitter)(nil), s)
	require.Implements(t, (*submitter.AttestationSubmitter)(nil), s)
	require.Implements(t, (*submitter.BeaconCommitteeSubscriptionsSubmitter)(nil), s)
	require.Implements(t, (*submitter.AggregateAttestationSubmitter)(nil), s)
}
