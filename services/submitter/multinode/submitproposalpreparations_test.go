// Copyright © 2022 Attestant Limited.
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
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/submitter/multinode"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSubmitProposalPreparationsEmpty(t *testing.T) {
	ctx := context.Background()

	s, err := multinode.New(context.Background(),
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(2*time.Second),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"1": mock.NewProposalSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"1": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"1": mock.NewAggregateAttestationsSubmitter(),
		}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{
			"1": mock.NewProposalPreparationsSubmitter(),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"1": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"1": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"1": mock.NewSyncCommitteeContributionsSubmitter(),
		}),
	)
	require.NoError(t, err)

	err = s.SubmitProposalPreparations(ctx, []*api.ProposalPreparation{})
	require.EqualError(t, err, "no proposal preparations supplied")
}

func TestSubmitProposalPreparations(t *testing.T) {
	ctx := context.Background()

	capture := logger.NewLogCapture()

	s, err := multinode.New(context.Background(),
		multinode.WithLogLevel(zerolog.TraceLevel),
		multinode.WithTimeout(100*time.Millisecond),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"1": mock.NewProposalSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"1": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"1": mock.NewAggregateAttestationsSubmitter(),
		}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{
			"1": mock.NewProposalPreparationsSubmitter(),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"1": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"1": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"1": mock.NewSyncCommitteeContributionsSubmitter(),
		}),
	)
	require.NoError(t, err)

	err = s.SubmitProposalPreparations(ctx, []*api.ProposalPreparation{
		{
			ValidatorIndex: 1,
			FeeRecipient:   bellatrix.ExecutionAddress{},
		},
	})
	require.NoError(t, err)

	// Return happens prior to the log message, so wait before asserting.
	time.Sleep(time.Millisecond)
	capture.AssertHasEntry(t, "Submitted proposal preparations")
}

func TestSubmitProposalPreparationsErroring(t *testing.T) {
	ctx := context.Background()

	s, err := multinode.New(context.Background(),
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(100*time.Millisecond),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"1": mock.NewProposalSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"1": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"1": mock.NewAggregateAttestationsSubmitter(),
		}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{
			"1": mock.NewErroringProposalPreparationsSubmitter(),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"1": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"1": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"1": mock.NewSyncCommitteeContributionsSubmitter(),
		}),
	)
	require.NoError(t, err)

	err = s.SubmitProposalPreparations(ctx, []*api.ProposalPreparation{
		{
			ValidatorIndex: 1,
			FeeRecipient:   bellatrix.ExecutionAddress{},
		},
	})
	require.EqualError(t, err, "no successful proposal preparations before timeout")
}

func TestSubmitProposalPreparationsSleepy(t *testing.T) {
	ctx := context.Background()

	s, err := multinode.New(context.Background(),
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(100*time.Millisecond),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"1": mock.NewProposalSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"1": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"1": mock.NewAggregateAttestationsSubmitter(),
		}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{
			"1": mock.NewSleepyProposalPreparationsSubmitter(200*time.Millisecond, mock.NewProposalPreparationsSubmitter()),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"1": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"1": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"1": mock.NewSyncCommitteeContributionsSubmitter(),
		}),
	)
	require.NoError(t, err)

	err = s.SubmitProposalPreparations(ctx, []*api.ProposalPreparation{
		{
			ValidatorIndex: 1,
			FeeRecipient:   bellatrix.ExecutionAddress{},
		},
	})
	require.EqualError(t, err, "no successful proposal preparations before timeout")
}

func TestSubmitProposalPreparationsSleepySuccess(t *testing.T) {
	ctx := context.Background()

	s, err := multinode.New(context.Background(),
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(200*time.Millisecond),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"1": mock.NewProposalSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"1": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"1": mock.NewAggregateAttestationsSubmitter(),
		}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{
			"1": mock.NewSleepyProposalPreparationsSubmitter(100*time.Millisecond, mock.NewProposalPreparationsSubmitter()),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"1": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"1": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"1": mock.NewSyncCommitteeContributionsSubmitter(),
		}),
	)
	require.NoError(t, err)

	err = s.SubmitProposalPreparations(ctx, []*api.ProposalPreparation{
		{
			ValidatorIndex: 1,
			FeeRecipient:   bellatrix.ExecutionAddress{},
		},
	})
	require.NoError(t, err)
}
