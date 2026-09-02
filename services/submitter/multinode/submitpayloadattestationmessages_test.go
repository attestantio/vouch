// Copyright © 2026 Attestant Limited.
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

package multinode_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	mocketh2client "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/vouch/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/services/submitter/multinode"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSubmitProposerPreferencesFansOutToNodes(t *testing.T) {
	ctx := context.Background()
	client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	recorderOne := &countingProposerPreferencesSubmitter{}
	recorderTwo := &countingProposerPreferencesSubmitter{}

	service, err := multinode.New(ctx,
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithClientMonitor(nullmetrics.New()),
		multinode.WithTimeout(time.Second),
		multinode.WithProcessConcurrency(2),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{"one": mock.NewProposalSubmitter()}),
		multinode.WithExecutionPayloadEnvelopeSubmitters(map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{"one": client}),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{"one": mock.NewAttestationsSubmitter()}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{"one": mock.NewAggregateAttestationsSubmitter()}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{"one": mock.NewProposalPreparationsSubmitter()}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{"one": mock.NewBeaconCommitteeSubscriptionsSubmitter()}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{"one": mock.NewSyncCommitteeMessagesSubmitter()}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{"one": mock.NewSyncCommitteeSubscriptionsSubmitter()}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{"one": mock.NewSyncCommitteeContributionsSubmitter()}),
		multinode.WithProposerPreferencesSubmitters(map[string]eth2client.ProposerPreferencesSubmitter{"one": recorderOne, "two": recorderTwo}),
	)
	require.NoError(t, err)

	outcomes := service.SubmitProposerPreferences(ctx, []*gloas.SignedProposerPreferences{{Message: &gloas.ProposerPreferences{}}}, nil)

	require.Equal(t, map[string]error{"one": nil, "two": nil}, outcomes)
	require.Eventually(t, func() bool {
		return recorderOne.calls.Load() == 1 && recorderTwo.calls.Load() == 1
	}, time.Second, 10*time.Millisecond)
}

func TestSubmitPayloadAttestationMessagesFansOutToNodes(t *testing.T) {
	ctx := context.Background()
	client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	recorderOne := &countingPayloadAttestationSubmitter{}
	recorderTwo := &countingPayloadAttestationSubmitter{}

	service, err := multinode.New(ctx,
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithClientMonitor(nullmetrics.New()),
		multinode.WithTimeout(time.Second),
		multinode.WithProcessConcurrency(2),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{"one": mock.NewProposalSubmitter()}),
		multinode.WithExecutionPayloadEnvelopeSubmitters(map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{"one": client}),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{"one": mock.NewAttestationsSubmitter()}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{"one": mock.NewAggregateAttestationsSubmitter()}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{"one": mock.NewProposalPreparationsSubmitter()}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{"one": mock.NewBeaconCommitteeSubscriptionsSubmitter()}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{"one": mock.NewSyncCommitteeMessagesSubmitter()}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{"one": mock.NewSyncCommitteeSubscriptionsSubmitter()}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{"one": mock.NewSyncCommitteeContributionsSubmitter()}),
		multinode.WithPayloadAttestationMessagesSubmitters(map[string]submitter.PayloadAttestationMessagesSubmitter{"one": recorderOne, "two": recorderTwo}),
	)
	require.NoError(t, err)

	opts := &api.SubmitPayloadAttestationMessagesOpts{Messages: []*spec.VersionedPayloadAttestationMessage{{Version: spec.DataVersionGloas}}}
	require.NoError(t, service.SubmitPayloadAttestationMessages(ctx, opts))
	// The call returns as soon as the first node succeeds, but every node must still be
	// submitted to; one node's success must not abort the others.
	require.Eventually(t, func() bool {
		return recorderOne.calls.Load() == 1 && recorderTwo.calls.Load() == 1
	}, time.Second, 10*time.Millisecond)
}

func TestSubmitPayloadAttestationMessagesContinuesAfterCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	canceled := make(chan struct{})
	completed := make(chan struct{})

	service, err := multinode.New(ctx,
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithClientMonitor(nullmetrics.New()),
		multinode.WithTimeout(time.Second),
		multinode.WithProcessConcurrency(2),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{"one": mock.NewProposalSubmitter()}),
		multinode.WithExecutionPayloadEnvelopeSubmitters(map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{"one": &capturingExecutionPayloadEnvelopeSubmitter{}}),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{"one": mock.NewAttestationsSubmitter()}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{"one": mock.NewAggregateAttestationsSubmitter()}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{"one": mock.NewProposalPreparationsSubmitter()}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{"one": mock.NewBeaconCommitteeSubscriptionsSubmitter()}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{"one": mock.NewSyncCommitteeMessagesSubmitter()}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{"one": mock.NewSyncCommitteeSubscriptionsSubmitter()}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{"one": mock.NewSyncCommitteeContributionsSubmitter()}),
		multinode.WithPayloadAttestationMessagesSubmitters(map[string]submitter.PayloadAttestationMessagesSubmitter{
			"slow": &cancelAwarePayloadAttestationSubmitter{started: started, release: release, canceled: canceled, completed: completed},
			"fast": &waitingPayloadAttestationSubmitter{started: started},
		}),
	)
	require.NoError(t, err)

	opts := &api.SubmitPayloadAttestationMessagesOpts{Messages: []*spec.VersionedPayloadAttestationMessage{{Version: spec.DataVersionGloas}}}
	require.NoError(t, service.SubmitPayloadAttestationMessages(ctx, opts))
	cancel()
	select {
	case <-canceled:
		t.Fatal("in-flight submission was canceled when the caller returned")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("in-flight submission did not complete")
	}
}

func TestSubmitPayloadAttestationMessagesReturnsOnFirstSuccess(t *testing.T) {
	ctx := context.Background()
	client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	started := make(chan struct{})
	canceled := make(chan struct{})

	service, err := multinode.New(ctx,
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithClientMonitor(nullmetrics.New()),
		multinode.WithTimeout(2*time.Second),
		multinode.WithProcessConcurrency(2),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{"one": mock.NewProposalSubmitter()}),
		multinode.WithExecutionPayloadEnvelopeSubmitters(map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{"one": client}),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{"one": mock.NewAttestationsSubmitter()}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{"one": mock.NewAggregateAttestationsSubmitter()}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{"one": mock.NewProposalPreparationsSubmitter()}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{"one": mock.NewBeaconCommitteeSubscriptionsSubmitter()}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{"one": mock.NewSyncCommitteeMessagesSubmitter()}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{"one": mock.NewSyncCommitteeSubscriptionsSubmitter()}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{"one": mock.NewSyncCommitteeContributionsSubmitter()}),
		multinode.WithPayloadAttestationMessagesSubmitters(map[string]submitter.PayloadAttestationMessagesSubmitter{
			"blocking": &blockingPayloadAttestationSubmitter{started: started, canceled: canceled},
			"success":  &waitingPayloadAttestationSubmitter{started: started},
		}),
	)
	require.NoError(t, err)

	opts := &api.SubmitPayloadAttestationMessagesOpts{Messages: []*spec.VersionedPayloadAttestationMessage{{Version: spec.DataVersionGloas}}}
	startedAt := time.Now()
	require.NoError(t, service.SubmitPayloadAttestationMessages(ctx, opts))
	require.Less(t, time.Since(startedAt), time.Second)
	// The fast node's success must not abort the slow node's in-flight submission; it runs on
	// until the strategy's own timeout.
	select {
	case <-canceled:
		t.Fatal("in-flight submission was aborted by another node's success")
	case <-time.After(250 * time.Millisecond):
	}
}

type countingProposerPreferencesSubmitter struct {
	calls atomic.Int32
}

func (s *countingProposerPreferencesSubmitter) SubmitProposerPreferences(_ context.Context, _ []*gloas.SignedProposerPreferences) error {
	s.calls.Add(1)
	return nil
}

type cancelAwarePayloadAttestationSubmitter struct {
	started   chan<- struct{}
	release   <-chan struct{}
	canceled  chan<- struct{}
	completed chan<- struct{}
}

func (s *cancelAwarePayloadAttestationSubmitter) SubmitPayloadAttestationMessages(ctx context.Context, _ *api.SubmitPayloadAttestationMessagesOpts) error {
	close(s.started)
	select {
	case <-ctx.Done():
		close(s.canceled)
		return ctx.Err()
	case <-s.release:
		close(s.completed)
		return nil
	}
}

type blockingPayloadAttestationSubmitter struct {
	started  chan<- struct{}
	canceled chan<- struct{}
}

func (s *blockingPayloadAttestationSubmitter) SubmitPayloadAttestationMessages(ctx context.Context, _ *api.SubmitPayloadAttestationMessagesOpts) error {
	close(s.started)
	<-ctx.Done()
	close(s.canceled)
	return ctx.Err()
}

type waitingPayloadAttestationSubmitter struct {
	started <-chan struct{}
}

func (s *waitingPayloadAttestationSubmitter) SubmitPayloadAttestationMessages(_ context.Context, _ *api.SubmitPayloadAttestationMessagesOpts) error {
	<-s.started
	return nil
}

type countingPayloadAttestationSubmitter struct {
	calls atomic.Int32
}

func (s *countingPayloadAttestationSubmitter) SubmitPayloadAttestationMessages(_ context.Context, _ *api.SubmitPayloadAttestationMessagesOpts) error {
	s.calls.Add(1)
	return nil
}
