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
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/services/submitter/immediate"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	attestationsSubmitter := mock.NewAttestationsSubmitter()
	beaconBlockSubmitter := mock.NewBeaconBlockSubmitter()
	beaconCommitteeSubscriptionSubmitter := mock.NewBeaconCommitteeSubscriptionsSubmitter()
	aggregateAttestationSubmitter := mock.NewAggregateAttestationsSubmitter()

	tests := []struct {
		name   string
		params []immediate.Parameter
		err    string
	}{
		{
			name: "AttestationsSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithBeaconBlockSubmitter(beaconBlockSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
			},
			err: "problem with parameters: no attestations submitter specified",
		},
		{
			name: "BeaconBlockSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
			},
			err: "problem with parameters: no beacon block submitter specified",
		},
		{
			name: "AttestationSubnetSubscriptionsSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
				immediate.WithBeaconBlockSubmitter(beaconBlockSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
			},
			err: "problem with parameters: no beacon committee subscriptions submitter specified",
		},
		{
			name: "AggregateAttestationSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
				immediate.WithBeaconBlockSubmitter(beaconBlockSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
			},
			err: "problem with parameters: no aggregate attestations submitter specified",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.TraceLevel),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
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
		immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
		immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
		immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
		immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
	)
	require.NoError(t, err)
	require.Implements(t, (*submitter.BeaconBlockSubmitter)(nil), s)
	require.Implements(t, (*submitter.AttestationsSubmitter)(nil), s)
	require.Implements(t, (*submitter.BeaconCommitteeSubscriptionsSubmitter)(nil), s)
	require.Implements(t, (*submitter.AggregateAttestationsSubmitter)(nil), s)
}

func TestSubmitBeaconBlock(t *testing.T) {
	tests := []struct {
		name   string
		params []immediate.Parameter
		block  *phase0.SignedBeaconBlock
		err    string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
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
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			block: &phase0.SignedBeaconBlock{},
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewErroringBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			block: &phase0.SignedBeaconBlock{},
			err:   "failed to submit beacon block: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.TraceLevel),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			block: &phase0.SignedBeaconBlock{},
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

func TestSubmitAttestations(t *testing.T) {
	tests := []struct {
		name         string
		params       []immediate.Parameter
		attestations []*phase0.Attestation
		err          string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			err: "no attestations supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			attestations: []*phase0.Attestation{},
			err:          "no attestations supplied",
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewErroringAttestationsSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			attestations: []*phase0.Attestation{{}},
			err:          "failed to submit attestations: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.TraceLevel),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			attestations: []*phase0.Attestation{{}},
		},
	}

	for _, test := range tests {
		s, err := immediate.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			err := s.SubmitAttestations(context.Background(), test.attestations)
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
		aggregates []*phase0.SignedAggregateAndProof
		err        string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
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
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			aggregates: []*phase0.SignedAggregateAndProof{},
			err:        "no aggregate attestations supplied",
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewErroringAggregateAttestationsSubmitter()),
			},
			aggregates: []*phase0.SignedAggregateAndProof{
				{},
			},
			err: "failed to submit aggregate attestation: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.TraceLevel),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
			},
			aggregates: []*phase0.SignedAggregateAndProof{
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
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
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
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
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
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
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
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
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
