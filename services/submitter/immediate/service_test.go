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
	"github.com/attestantio/go-eth2-client/spec"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/services/submitter/immediate"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	attestationsSubmitter := mock.NewAttestationsSubmitter()
	proposalSubmitter := mock.NewProposalSubmitter()
	beaconCommitteeSubscriptionSubmitter := mock.NewBeaconCommitteeSubscriptionsSubmitter()
	aggregateAttestationSubmitter := mock.NewAggregateAttestationsSubmitter()
	proposalPreparationsSubmitter := mock.NewProposalPreparationsSubmitter()
	syncCommitteeMessagesSubmitter := mock.NewSyncCommitteeMessagesSubmitter()
	syncCommitteeSubscriptionsSubmitter := mock.NewSyncCommitteeSubscriptionsSubmitter()
	syncCommitteeContributionsSubmitter := mock.NewSyncCommitteeContributionsSubmitter()

	tests := []struct {
		name   string
		params []immediate.Parameter
		err    string
	}{
		{
			name: "ClientMonitorMisssing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithClientMonitor(nil),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
				immediate.WithProposalSubmitter(proposalSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
				immediate.WithProposalPreparationsSubmitter(proposalPreparationsSubmitter),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(syncCommitteeSubscriptionsSubmitter),
				immediate.WithSyncCommitteeMessagesSubmitter(syncCommitteeMessagesSubmitter),
				immediate.WithSyncCommitteeContributionsSubmitter(syncCommitteeContributionsSubmitter),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "AttestationsSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithProposalSubmitter(proposalSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
				immediate.WithProposalPreparationsSubmitter(proposalPreparationsSubmitter),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(syncCommitteeSubscriptionsSubmitter),
				immediate.WithSyncCommitteeMessagesSubmitter(syncCommitteeMessagesSubmitter),
				immediate.WithSyncCommitteeContributionsSubmitter(syncCommitteeContributionsSubmitter),
			},
			err: "problem with parameters: no attestations submitter specified",
		},
		{
			name: "ProposalSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
				immediate.WithProposalPreparationsSubmitter(proposalPreparationsSubmitter),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(syncCommitteeSubscriptionsSubmitter),
				immediate.WithSyncCommitteeMessagesSubmitter(syncCommitteeMessagesSubmitter),
				immediate.WithSyncCommitteeContributionsSubmitter(syncCommitteeContributionsSubmitter),
			},
			err: "problem with parameters: no proposal submitter specified",
		},
		{
			name: "AttestationSubnetSubscriptionsSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
				immediate.WithProposalSubmitter(proposalSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
				immediate.WithProposalPreparationsSubmitter(proposalPreparationsSubmitter),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(syncCommitteeSubscriptionsSubmitter),
				immediate.WithSyncCommitteeMessagesSubmitter(syncCommitteeMessagesSubmitter),
				immediate.WithSyncCommitteeContributionsSubmitter(syncCommitteeContributionsSubmitter),
			},
			err: "problem with parameters: no beacon committee subscriptions submitter specified",
		},
		{
			name: "AggregateAttestationSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
				immediate.WithProposalSubmitter(proposalSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithProposalPreparationsSubmitter(proposalPreparationsSubmitter),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(syncCommitteeSubscriptionsSubmitter),
				immediate.WithSyncCommitteeMessagesSubmitter(syncCommitteeMessagesSubmitter),
				immediate.WithSyncCommitteeContributionsSubmitter(syncCommitteeContributionsSubmitter),
			},
			err: "problem with parameters: no aggregate attestations submitter specified",
		},
		{
			name: "ProposalPreparationsSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
				immediate.WithProposalSubmitter(proposalSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(syncCommitteeSubscriptionsSubmitter),
				immediate.WithSyncCommitteeMessagesSubmitter(syncCommitteeMessagesSubmitter),
				immediate.WithSyncCommitteeContributionsSubmitter(syncCommitteeContributionsSubmitter),
			},
			err: "problem with parameters: no proposal preparations submitter specified",
		},
		{
			name: "SyncCommitteeSubscriptionsSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
				immediate.WithProposalSubmitter(proposalSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
				immediate.WithProposalPreparationsSubmitter(proposalPreparationsSubmitter),
				immediate.WithSyncCommitteeMessagesSubmitter(syncCommitteeMessagesSubmitter),
				immediate.WithSyncCommitteeContributionsSubmitter(syncCommitteeContributionsSubmitter),
			},
			err: "problem with parameters: no sync committee subscriptions submitter specified",
		},
		{
			name: "SyncCommitteeMessagesSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
				immediate.WithProposalSubmitter(proposalSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
				immediate.WithProposalPreparationsSubmitter(proposalPreparationsSubmitter),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(syncCommitteeSubscriptionsSubmitter),
				immediate.WithSyncCommitteeContributionsSubmitter(syncCommitteeContributionsSubmitter),
			},
			err: "problem with parameters: no sync committee messages submitter specified",
		},
		{
			name: "SyncCommitteeContributionsSubmitterMissing",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
				immediate.WithProposalSubmitter(proposalSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
				immediate.WithProposalPreparationsSubmitter(proposalPreparationsSubmitter),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(syncCommitteeSubscriptionsSubmitter),
				immediate.WithSyncCommitteeMessagesSubmitter(syncCommitteeMessagesSubmitter),
			},
			err: "problem with parameters: no sync committee contributions submitter specified",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(attestationsSubmitter),
				immediate.WithProposalSubmitter(proposalSubmitter),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(beaconCommitteeSubscriptionSubmitter),
				immediate.WithAggregateAttestationsSubmitter(aggregateAttestationSubmitter),
				immediate.WithProposalPreparationsSubmitter(proposalPreparationsSubmitter),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(syncCommitteeSubscriptionsSubmitter),
				immediate.WithSyncCommitteeMessagesSubmitter(syncCommitteeMessagesSubmitter),
				immediate.WithSyncCommitteeContributionsSubmitter(syncCommitteeContributionsSubmitter),
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
		immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
		immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
		immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
		immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
		immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
		immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
		immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
	)
	require.NoError(t, err)
	require.Implements(t, (*submitter.ProposalSubmitter)(nil), s)
	require.Implements(t, (*submitter.AttestationsSubmitter)(nil), s)
	require.Implements(t, (*submitter.BeaconCommitteeSubscriptionsSubmitter)(nil), s)
	require.Implements(t, (*submitter.AggregateAttestationsSubmitter)(nil), s)
	require.Implements(t, (*submitter.ProposalPreparationsSubmitter)(nil), s)
	require.Implements(t, (*submitter.SyncCommitteeMessagesSubmitter)(nil), s)
	require.Implements(t, (*submitter.SyncCommitteeSubscriptionsSubmitter)(nil), s)
	require.Implements(t, (*submitter.SyncCommitteeContributionsSubmitter)(nil), s)
}

func TestSubmitProposal(t *testing.T) {
	tests := []struct {
		name     string
		params   []immediate.Parameter
		proposal *api.VersionedSignedProposal
		err      string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			err: "no proposal supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			proposal: &api.VersionedSignedProposal{},
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewErroringProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			proposal: &api.VersionedSignedProposal{},
			err:      "failed to submit proposal: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			proposal: &api.VersionedSignedProposal{},
		},
	}

	for _, test := range tests {
		s, err := immediate.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			err := s.SubmitProposal(context.Background(), test.proposal)
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
		attestations []*spec.VersionedAttestation
		err          string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			err: "no attestations supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			attestations: []*spec.VersionedAttestation{},
			err:          "no attestations supplied",
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewErroringAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			attestations: []*spec.VersionedAttestation{{}},
			err:          "failed to submit attestations: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			attestations: []*spec.VersionedAttestation{{}},
		},
	}

	for _, test := range tests {
		s, err := immediate.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			opts := &api.SubmitAttestationsOpts{
				Attestations: test.attestations,
			}
			err := s.SubmitAttestations(context.Background(), opts)
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
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			err: "no aggregate attestations supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			aggregates: []*phase0.SignedAggregateAndProof{},
			err:        "no aggregate attestations supplied",
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewErroringAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			aggregates: []*phase0.SignedAggregateAndProof{
				{},
			},
			err: "failed to submit aggregate attestation: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
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

func TestSubmitProposalPreparations(t *testing.T) {
	tests := []struct {
		name         string
		params       []immediate.Parameter
		preparations []*apiv1.ProposalPreparation
		err          string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			err: "no proposal preparations supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			preparations: []*apiv1.ProposalPreparation{},
			err:          "no proposal preparations supplied",
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewErroringAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewErroringProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			preparations: []*apiv1.ProposalPreparation{
				{},
			},
			err: "failed to submit proposal preparations: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			preparations: []*apiv1.ProposalPreparation{
				{},
			},
		},
	}

	for _, test := range tests {
		s, err := immediate.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			err := s.SubmitProposalPreparations(context.Background(), test.preparations)
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
		subscriptions []*apiv1.BeaconCommitteeSubscription
		err           string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			err: "no beacon committee subscriptions supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			subscriptions: []*apiv1.BeaconCommitteeSubscription{},
			err:           "no beacon committee subscriptions supplied",
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewErroringBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			subscriptions: []*apiv1.BeaconCommitteeSubscription{
				{},
			},
			err: "failed to submit beacon committee subscriptions: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			subscriptions: []*apiv1.BeaconCommitteeSubscription{
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

func TestSubmitSyncCommitteeSubscriptions(t *testing.T) {
	tests := []struct {
		name          string
		params        []immediate.Parameter
		subscriptions []*apiv1.SyncCommitteeSubscription
		err           string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			err: "no sync committee subscriptions supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			subscriptions: []*apiv1.SyncCommitteeSubscription{},
			err:           "no sync committee subscriptions supplied",
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewErroringSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			subscriptions: []*apiv1.SyncCommitteeSubscription{
				{},
			},
			err: "failed to submit sync committee subscriptions: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			subscriptions: []*apiv1.SyncCommitteeSubscription{
				{},
			},
		},
	}

	for _, test := range tests {
		s, err := immediate.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			err := s.SubmitSyncCommitteeSubscriptions(context.Background(), test.subscriptions)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSubmitSyncCommitteeMessages(t *testing.T) {
	tests := []struct {
		name     string
		params   []immediate.Parameter
		messages []*altair.SyncCommitteeMessage
		err      string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			err: "no sync committee messages supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			messages: []*altair.SyncCommitteeMessage{},
			err:      "no sync committee messages supplied",
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewErroringSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			messages: []*altair.SyncCommitteeMessage{
				{},
			},
			err: "failed to submit sync committee messages: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			messages: []*altair.SyncCommitteeMessage{
				{},
			},
		},
	}

	for _, test := range tests {
		s, err := immediate.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			err := s.SubmitSyncCommitteeMessages(context.Background(), test.messages)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSubmitSyncCommitteeContributions(t *testing.T) {
	tests := []struct {
		name          string
		params        []immediate.Parameter
		contributions []*altair.SignedContributionAndProof
		err           string
	}{
		{
			name: "Nil",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			err: "no sync committee contribution and proofs supplied",
		},
		{
			name: "Empty",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			contributions: []*altair.SignedContributionAndProof{},
			err:           "no sync committee contribution and proofs supplied",
		},
		{
			name: "Erroring",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewErroringSyncCommitteeContributionsSubmitter()),
			},
			contributions: []*altair.SignedContributionAndProof{
				{},
			},
			err: "failed to submit sync committee contribution and proofs: error",
		},
		{
			name: "Good",
			params: []immediate.Parameter{
				immediate.WithLogLevel(zerolog.Disabled),
				immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
				immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
				immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
				immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
				immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
				immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
				immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
			},
			contributions: []*altair.SignedContributionAndProof{
				{},
			},
		},
	}

	for _, test := range tests {
		s, err := immediate.New(context.Background(), test.params...)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			err := s.SubmitSyncCommitteeContributions(context.Background(), test.contributions)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
