// Copyright © 2020 - 2026 Attestant Limited.
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
	mockconsensusclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/services/submitter/multinode"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	ctx := context.Background()
	executionPayloadEnvelopeSubmitter, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	executionPayloadEnvelopeSubmitters := map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{
		"1": executionPayloadEnvelopeSubmitter,
	}
	attestationsSubmitters := map[string]eth2client.AttestationsSubmitter{
		"1": mock.NewAttestationsSubmitter(),
	}
	beaconBlockSubmitters := map[string]eth2client.ProposalSubmitter{
		"1": mock.NewProposalSubmitter(),
	}
	beaconCommitteeSubscriptionsSubmitters := map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
		"1": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
	}
	aggregateAttestationsSubmitters := map[string]eth2client.AggregateAttestationsSubmitter{
		"1": mock.NewAggregateAttestationsSubmitter(),
	}
	proposalPrepartionsSubmitters := map[string]eth2client.ProposalPreparationsSubmitter{
		"1": mock.NewProposalPreparationsSubmitter(),
	}
	syncCommitteeMessagesSubmitters := map[string]eth2client.SyncCommitteeMessagesSubmitter{
		"1": mock.NewSyncCommitteeMessagesSubmitter(),
	}
	syncCommitteeSubscriptionsSubmitters := map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
		"1": mock.NewSyncCommitteeSubscriptionsSubmitter(),
	}
	syncCommitteeContributionsSubmitters := map[string]eth2client.SyncCommitteeContributionsSubmitter{
		"1": mock.NewSyncCommitteeContributionsSubmitter(),
	}
	tests := []struct {
		name   string
		params []multinode.Parameter
		err    string
	}{
		{
			name: "ClientMonitorMissing",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithClientMonitor(nil),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "TimeoutZero",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(0),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no timeout specified",
		},
		{
			name: "ProcessConcurrencyZero",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(0),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no process concurrency specified",
		},
		{
			name: "ProposalSubmittersMissing",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no proposal submitters specified",
		},
		{
			name: "ProposalSubmittersEmpty",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{}),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no proposal submitters specified",
		},
		{
			name: "AttestationsSubmittersMissing",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no attestations submitters specified",
		},
		{
			name: "AttestationsSubmittersEmpty",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{}),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no attestations submitters specified",
		},
		{
			name: "BeaconCommitteeSubscriptionsSubmittersMissing",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no beacon committee subscription submitters specified",
		},
		{
			name: "BeaconCommitteeSubscriptionsSubmittersEmpty",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{}),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no beacon committee subscription submitters specified",
		},
		{
			name: "AggregateAttestationsSubmittersMissing",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no aggregate attestations submitters specified",
		},
		{
			name: "AggregateAttestationsSubmittersEmpty",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{}),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no aggregate attestations submitters specified",
		},
		{
			name: "ProposalPreparationsSubmittersMissing",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no proposal preparations submitters specified",
		},
		{
			name: "ProposalPreparationsSubmittersEmpty",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{}),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no proposal preparations submitters specified",
		},
		{
			name: "SyncCommitteeMessagesSubmittersMissing",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no sync committee messages submitters specified",
		},
		{
			name: "SyncCommitteeMessagesSubmittersEmpty",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{}),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no sync committee messages submitters specified",
		},
		{
			name: "SyncCommitteeSubscriptionsSubmittersMissing",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no sync committee subscriptions submitters specified",
		},
		{
			name: "SyncCommitteeSubscriptionsSubmittersEmpty",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{}),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no sync committee subscriptions submitters specified",
		},
		{
			name: "SyncCommitteeContributionsSubmittersMissing",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
			},
			err: "problem with parameters: no sync committee contributions submitters specified",
		},
		{
			name: "SyncCommitteeContributionsSubmittersEmpty",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{}),
			},
			err: "problem with parameters: no sync committee contributions submitters specified",
		},
		{
			name: "ExecutionPayloadEnvelopeSubmittersMissing",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no execution payload envelope submitters specified",
		},
		{
			name: "ExecutionPayloadEnvelopeSubmittersEmpty",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithExecutionPayloadEnvelopeSubmitters(map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{}),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
			err: "problem with parameters: no execution payload envelope submitters specified",
		},
		{
			name: "Good",
			params: []multinode.Parameter{
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(2 * time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithProposalSubmitters(beaconBlockSubmitters),
				multinode.WithAttestationsSubmitters(attestationsSubmitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(beaconCommitteeSubscriptionsSubmitters),
				multinode.WithAggregateAttestationsSubmitters(aggregateAttestationsSubmitters),
				multinode.WithProposalPreparationsSubmitters(proposalPrepartionsSubmitters),
				multinode.WithSyncCommitteeMessagesSubmitters(syncCommitteeMessagesSubmitters),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(syncCommitteeSubscriptionsSubmitters),
				multinode.WithSyncCommitteeContributionsSubmitters(syncCommitteeContributionsSubmitters),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params := test.params
			if test.name != "ExecutionPayloadEnvelopeSubmittersMissing" && test.name != "ExecutionPayloadEnvelopeSubmittersEmpty" {
				params = append(params, multinode.WithExecutionPayloadEnvelopeSubmitters(executionPayloadEnvelopeSubmitters))
			}
			_, err := multinode.New(ctx, params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func newTestService(ctx context.Context, params ...multinode.Parameter) (*multinode.Service, error) {
	executionPayloadEnvelopeSubmitter, err := mockconsensusclient.New(ctx)
	if err != nil {
		return nil, err
	}
	params = append(params, multinode.WithExecutionPayloadEnvelopeSubmitters(map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{
		"1": executionPayloadEnvelopeSubmitter,
	}))

	return multinode.New(ctx, params...)
}

func TestInterfaces(t *testing.T) {
	s, err := newTestService(context.Background(),
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
	require.Implements(t, (*submitter.ProposalSubmitter)(nil), s)
	require.Implements(t, (*submitter.AttestationsSubmitter)(nil), s)
	require.Implements(t, (*submitter.BeaconCommitteeSubscriptionsSubmitter)(nil), s)
	require.Implements(t, (*submitter.AggregateAttestationsSubmitter)(nil), s)
	require.Implements(t, (*submitter.ProposalPreparationsSubmitter)(nil), s)
	require.Implements(t, (*submitter.SyncCommitteeMessagesSubmitter)(nil), s)
	require.Implements(t, (*submitter.SyncCommitteeSubscriptionsSubmitter)(nil), s)
	require.Implements(t, (*submitter.SyncCommitteeContributionsSubmitter)(nil), s)
}
