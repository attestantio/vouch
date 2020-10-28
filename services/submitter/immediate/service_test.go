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

	api "github.com/attestantio/go-eth2-client/api/v1"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
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
				immediate.WithLogLevel(zerolog.TraceLevel),
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
	require.Implements(t, (*submitter.AggregateAttestationsSubmitter)(nil), s)
}

func TestSubmitBeaconBlock(t *testing.T) {
	tests := []struct {
		name   string
		params []immediate.Parameter
		block  *spec.SignedBeaconBlock
		err    string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			err: "no beacon block supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			block: &spec.SignedBeaconBlock{},
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewErroringBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			block: &spec.SignedBeaconBlock{},
			err:   "failed to submit beacon block: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.TraceLevel),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			block: &spec.SignedBeaconBlock{},
		},
	}

	for _, test := range tests {
		s, err := immediate.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			err := s.SubmitBeaconBlock(context.Background(), test.block)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSubmitAttestation(t *testing.T) {
	tests := []struct {
		name        string
		params      []immediate.Parameter
		attestation *spec.Attestation
		err         string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			err: "no attestation supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			attestation: &spec.Attestation{},
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(mock.NewErroringAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			attestation: &spec.Attestation{},
			err:         "failed to submit attestation: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.TraceLevel),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			attestation: &spec.Attestation{},
		},
	}

	for _, test := range tests {
		s, err := immediate.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			err := s.SubmitAttestation(context.Background(), test.attestation)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSubmitAggregateAttestations(t *testing.T) {
	tests := []struct {
		name       string
		params     []immediate.Parameter
		aggregates []*spec.SignedAggregateAndProof
		err        string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			err: "no aggregate attestations supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			aggregates: []*spec.SignedAggregateAndProof{},
			err:        "no aggregate attestations supplied",
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewErroringAggregateAttestationsSubmitter()),
			},
			aggregates: []*spec.SignedAggregateAndProof{
				{},
			},
			err: "failed to submit aggregate attestation: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.TraceLevel),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			aggregates: []*spec.SignedAggregateAndProof{
				{},
			},
		},
	}

	for _, test := range tests {
		s, err := immediate.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			err := s.SubmitAggregateAttestations(context.Background(), test.aggregates)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSubmitBeaconCommitteeSubscriptions(t *testing.T) {
	tests := []struct {
		name          string
		params        []immediate.Parameter
		subscriptions []*api.BeaconCommitteeSubscription
		err           string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			err: "no beacon committee subscriptions supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			subscriptions: []*api.BeaconCommitteeSubscription{},
			err:           "no beacon committee subscriptions supplied",
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewErroringBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			subscriptions: []*api.BeaconCommitteeSubscription{
				{},
			},
			err: "failed to submit beacon committee subscriptions: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.TraceLevel),
				immediate.WithAttestationSubmitter(mock.NewAttestationSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			subscriptions: []*api.BeaconCommitteeSubscription{
				{},
			},
		},
	}

	for _, test := range tests {
		s, err := immediate.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			err := s.SubmitBeaconCommitteeSubscriptions(context.Background(), test.subscriptions)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
