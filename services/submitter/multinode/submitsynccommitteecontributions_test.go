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
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/submitter/multinode"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSubmitSyncCommitteeContributionsEmpty(t *testing.T) {
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
		multinode.WithVersionedAttestationsSubmitters(map[string]eth2client.VersionedAttestationsSubmitter{
			"1": mock.NewVersionedAttestationsSubmitter(),
		}),
	)
	require.NoError(t, err)

	err = s.SubmitSyncCommitteeContributions(ctx, []*altair.SignedContributionAndProof{})
	require.EqualError(t, err, "no sync committee contribution and proofs supplied")
}

func TestSubmitSyncCommitteeContributions(t *testing.T) {
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
		multinode.WithVersionedAttestationsSubmitters(map[string]eth2client.VersionedAttestationsSubmitter{
			"1": mock.NewVersionedAttestationsSubmitter(),
		}),
	)
	require.NoError(t, err)

	err = s.SubmitSyncCommitteeContributions(ctx, []*altair.SignedContributionAndProof{
		{
			Message: &altair.ContributionAndProof{
				Contribution: &altair.SyncCommitteeContribution{
					Slot: 5,
				},
			},
		},
	})
	require.NoError(t, err)

	// Return happens prior to the log message, so wait before asserting.
	time.Sleep(time.Millisecond)
	capture.AssertHasEntry(t, "Submitted sync committee contribution and proofs")
}

func TestSubmitSyncCommitteeContributionsErroring(t *testing.T) {
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
			"1": mock.NewProposalPreparationsSubmitter(),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"1": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"1": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"1": mock.NewErroringSyncCommitteeContributionsSubmitter(),
		}),
		multinode.WithVersionedAttestationsSubmitters(map[string]eth2client.VersionedAttestationsSubmitter{
			"1": mock.NewVersionedAttestationsSubmitter(),
		}),
	)
	require.NoError(t, err)

	err = s.SubmitSyncCommitteeContributions(ctx, []*altair.SignedContributionAndProof{
		{
			Message: &altair.ContributionAndProof{
				Contribution: &altair.SyncCommitteeContribution{
					Slot: 5,
				},
			},
		},
	})
	require.EqualError(t, err, "no successful submissions before timeout")
}

func TestSubmitSyncCommitteeContributionsSleepy(t *testing.T) {
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
			"1": mock.NewProposalPreparationsSubmitter(),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"1": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"1": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"1": mock.NewSleepySyncCommitteeContributionsSubmitter(200*time.Millisecond, mock.NewSyncCommitteeContributionsSubmitter()),
		}),
		multinode.WithVersionedAttestationsSubmitters(map[string]eth2client.VersionedAttestationsSubmitter{
			"1": mock.NewVersionedAttestationsSubmitter(),
		}),
	)
	require.NoError(t, err)

	err = s.SubmitSyncCommitteeContributions(ctx, []*altair.SignedContributionAndProof{
		{
			Message: &altair.ContributionAndProof{
				Contribution: &altair.SyncCommitteeContribution{
					Slot: 5,
				},
			},
		},
	})
	require.EqualError(t, err, "no successful submissions before timeout")
}

func TestSubmitSyncCommitteeContributionsSleepySuccess(t *testing.T) {
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
			"1": mock.NewProposalPreparationsSubmitter(),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"1": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"1": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"1": mock.NewSleepySyncCommitteeContributionsSubmitter(100*time.Millisecond, mock.NewSyncCommitteeContributionsSubmitter()),
		}),
		multinode.WithVersionedAttestationsSubmitters(map[string]eth2client.VersionedAttestationsSubmitter{
			"1": mock.NewVersionedAttestationsSubmitter(),
		}),
	)
	require.NoError(t, err)

	err = s.SubmitSyncCommitteeContributions(ctx, []*altair.SignedContributionAndProof{
		{
			Message: &altair.ContributionAndProof{
				Contribution: &altair.SyncCommitteeContribution{
					Slot: 5,
				},
			},
		},
	})
	require.NoError(t, err)
}
