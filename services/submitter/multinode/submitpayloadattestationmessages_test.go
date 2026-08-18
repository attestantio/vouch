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
	"github.com/attestantio/vouch/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/services/submitter/multinode"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

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
	require.GreaterOrEqual(t, atomic.LoadInt32(&recorderOne.calls)+atomic.LoadInt32(&recorderTwo.calls), int32(1))
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
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("blocking submitter was not canceled")
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
	calls int32
}

func (s *countingPayloadAttestationSubmitter) SubmitPayloadAttestationMessages(_ context.Context, _ *api.SubmitPayloadAttestationMessagesOpts) error {
	atomic.AddInt32(&s.calls, 1)
	return nil
}
