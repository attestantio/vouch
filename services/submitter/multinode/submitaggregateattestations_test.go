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
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/submitter/multinode"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/attestantio/vouch/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSubmitAggregateAttestationsEmpty(t *testing.T) {
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
	opts := &api.SubmitAggregateAttestationsOpts{
		Common:                   api.CommonOpts{},
		SignedAggregateAndProofs: []*spec.VersionedSignedAggregateAndProof{},
	}
	err = s.SubmitAggregateAttestations(ctx, opts)
	require.EqualError(t, err, "no aggregate attestations supplied")
}

func TestSubmitAggregateAttestations(t *testing.T) {
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
	signedProofs := []*spec.VersionedSignedAggregateAndProof{
		{
			Version: spec.DataVersionPhase0,
			Phase0: &phase0.SignedAggregateAndProof{
				Message: &phase0.AggregateAndProof{
					Aggregate: &phase0.Attestation{
						Data: &phase0.AttestationData{
							BeaconBlockRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
							Source: &phase0.Checkpoint{
								Epoch: 5,
								Root:  testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
							},
							Target: &phase0.Checkpoint{
								Epoch: 6,
								Root:  testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
							},
						},
					},
				},
				Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
			},
		},
	}
	opts := &api.SubmitAggregateAttestationsOpts{
		Common:                   api.CommonOpts{},
		SignedAggregateAndProofs: signedProofs,
	}
	err = s.SubmitAggregateAttestations(ctx, opts)
	require.NoError(t, err)

	// Return happens prior to the log message, so wait before asserting.
	time.Sleep(time.Millisecond)
	capture.AssertHasEntry(t, "Submitted aggregate attestations")
}

func TestSubmitAggregateAttestationsErroring(t *testing.T) {
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
			"1": mock.NewErroringAggregateAttestationsSubmitter(),
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

	signedProofs := []*spec.VersionedSignedAggregateAndProof{
		{
			Version: spec.DataVersionPhase0,
			Phase0: &phase0.SignedAggregateAndProof{
				Message: &phase0.AggregateAndProof{
					Aggregate: &phase0.Attestation{
						Data: &phase0.AttestationData{
							BeaconBlockRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
							Source: &phase0.Checkpoint{
								Epoch: 5,
								Root:  testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
							},
							Target: &phase0.Checkpoint{
								Epoch: 6,
								Root:  testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
							},
						},
					},
				},
				Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
			},
		},
	}
	opts := &api.SubmitAggregateAttestationsOpts{
		Common:                   api.CommonOpts{},
		SignedAggregateAndProofs: signedProofs,
	}
	err = s.SubmitAggregateAttestations(ctx, opts)
	require.EqualError(t, err, "no successful submissions before timeout")
}

func TestSubmitAggregateAttestationsSleepy(t *testing.T) {
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
			"1": mock.NewSleepyAggregateAttestationsSubmitter(200*time.Millisecond, mock.NewAggregateAttestationsSubmitter()),
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

	signedProofs := []*spec.VersionedSignedAggregateAndProof{
		{
			Version: spec.DataVersionPhase0,
			Phase0: &phase0.SignedAggregateAndProof{
				Message: &phase0.AggregateAndProof{
					Aggregate: &phase0.Attestation{
						Data: &phase0.AttestationData{
							BeaconBlockRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
							Source: &phase0.Checkpoint{
								Epoch: 5,
								Root:  testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
							},
							Target: &phase0.Checkpoint{
								Epoch: 6,
								Root:  testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
							},
						},
					},
				},
				Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
			},
		},
	}
	opts := &api.SubmitAggregateAttestationsOpts{
		Common:                   api.CommonOpts{},
		SignedAggregateAndProofs: signedProofs,
	}
	err = s.SubmitAggregateAttestations(ctx, opts)
	require.EqualError(t, err, "no successful submissions before timeout")
}

func TestSubmitAggregateAttestationsSleepySuccess(t *testing.T) {
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
			"1": mock.NewSleepyAggregateAttestationsSubmitter(100*time.Millisecond, mock.NewAggregateAttestationsSubmitter()),
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

	signedProofs := []*spec.VersionedSignedAggregateAndProof{
		{
			Version: spec.DataVersionPhase0,
			Phase0: &phase0.SignedAggregateAndProof{
				Message: &phase0.AggregateAndProof{
					Aggregate: &phase0.Attestation{
						Data: &phase0.AttestationData{
							BeaconBlockRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
							Source: &phase0.Checkpoint{
								Epoch: 5,
								Root:  testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
							},
							Target: &phase0.Checkpoint{
								Epoch: 6,
								Root:  testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
							},
						},
					},
				},
				Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
			},
		},
	}
	opts := &api.SubmitAggregateAttestationsOpts{
		Common:                   api.CommonOpts{},
		SignedAggregateAndProofs: signedProofs,
	}
	err = s.SubmitAggregateAttestations(ctx, opts)
	require.NoError(t, err)
}
