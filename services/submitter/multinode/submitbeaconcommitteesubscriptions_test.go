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
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/submitter/multinode"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSubmitBeaconCommitteeSubscriptionsEmpty(t *testing.T) {
	ctx := context.Background()

	s, err := multinode.New(context.Background(),
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(2*time.Second),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithBeaconBlockSubmitters(map[string]eth2client.BeaconBlockSubmitter{
			"1": mock.NewBeaconBlockSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"1": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"1": mock.NewAggregateAttestationsSubmitter(),
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

	err = s.SubmitBeaconCommitteeSubscriptions(ctx, []*api.BeaconCommitteeSubscription{})
	require.NoError(t, err)
}

func TestSubmitBeaconCommitteeSubscriptions(t *testing.T) {
	ctx := context.Background()

	capture := logger.NewLogCapture()

	s, err := multinode.New(context.Background(),
		multinode.WithLogLevel(zerolog.TraceLevel),
		multinode.WithTimeout(100*time.Millisecond),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithBeaconBlockSubmitters(map[string]eth2client.BeaconBlockSubmitter{
			"1": mock.NewBeaconBlockSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"1": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"1": mock.NewAggregateAttestationsSubmitter(),
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

	err = s.SubmitBeaconCommitteeSubscriptions(ctx, []*api.BeaconCommitteeSubscription{
		{},
	})
	require.NoError(t, err)
	capture.AssertHasEntry(t, "Submitted beacon committee subscriptions")
}

func TestSubmitBeaconCommitteeSubscriptionsErroring(t *testing.T) {
	ctx := context.Background()

	s, err := multinode.New(context.Background(),
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(100*time.Millisecond),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithBeaconBlockSubmitters(map[string]eth2client.BeaconBlockSubmitter{
			"1": mock.NewBeaconBlockSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"1": mock.NewErroringBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"1": mock.NewAggregateAttestationsSubmitter(),
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

	err = s.SubmitBeaconCommitteeSubscriptions(ctx, []*api.BeaconCommitteeSubscription{
		{},
	})
	require.EqualError(t, err, "no successful submissions before timeout")
}

func TestSubmitBeaconCommitteeSubscriptionsSleepy(t *testing.T) {
	ctx := context.Background()

	s, err := multinode.New(context.Background(),
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(100*time.Millisecond),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithBeaconBlockSubmitters(map[string]eth2client.BeaconBlockSubmitter{
			"1": mock.NewBeaconBlockSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"1": mock.NewSleepyBeaconCommitteeSubscriptionsSubmitter(200*time.Millisecond, mock.NewBeaconCommitteeSubscriptionsSubmitter()),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"1": mock.NewAggregateAttestationsSubmitter(),
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

	err = s.SubmitBeaconCommitteeSubscriptions(ctx, []*api.BeaconCommitteeSubscription{
		{},
	})
	require.EqualError(t, err, "no successful submissions before timeout")
}

func TestSubmitBeaconCommitteeSubscriptionsSleepySuccess(t *testing.T) {
	ctx := context.Background()

	s, err := multinode.New(context.Background(),
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(200*time.Millisecond),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithBeaconBlockSubmitters(map[string]eth2client.BeaconBlockSubmitter{
			"1": mock.NewBeaconBlockSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"1": mock.NewSleepyBeaconCommitteeSubscriptionsSubmitter(100*time.Millisecond, mock.NewBeaconCommitteeSubscriptionsSubmitter()),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"1": mock.NewAggregateAttestationsSubmitter(),
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

	err = s.SubmitBeaconCommitteeSubscriptions(ctx, []*api.BeaconCommitteeSubscription{
		{},
	})
	require.NoError(t, err)
}
