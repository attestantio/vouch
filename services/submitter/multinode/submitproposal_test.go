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
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2http "github.com/attestantio/go-eth2-client/http"
	mockconsensusclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/submitter/multinode"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSubmitProposalEmpty(t *testing.T) {
	ctx := context.Background()

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

	err = s.SubmitProposal(ctx, nil)
	require.EqualError(t, err, "no proposal supplied")
}

func TestSubmitProposal(t *testing.T) {
	ctx := context.Background()

	capture := logger.NewLogCapture()

	s, err := newTestService(context.Background(),
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

	err = s.SubmitProposal(ctx, &api.SubmitProposalOpts{Proposal: &api.VersionedSignedProposal{
		Version: spec.DataVersionDeneb,
		Deneb: &apiv1deneb.SignedBlockContents{
			SignedBlock: &deneb.SignedBeaconBlock{
				Message: &deneb.BeaconBlock{
					Slot: 1,
				},
			},
		},
	}})
	require.NoError(t, err)

	// Return happens prior to the log message, so wait before asserting.
	time.Sleep(time.Millisecond)
	capture.AssertHasEntry(t, "Submitted proposal")
}

func TestSubmitProposalErroring(t *testing.T) {
	ctx := context.Background()

	s, err := newTestService(context.Background(),
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(100*time.Millisecond),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"1": mock.NewErroringProposalSubmitter(),
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

	err = s.SubmitProposal(ctx, &api.SubmitProposalOpts{Proposal: &api.VersionedSignedProposal{
		Version: spec.DataVersionDeneb,
		Deneb: &apiv1deneb.SignedBlockContents{
			SignedBlock: &deneb.SignedBeaconBlock{
				Message: &deneb.BeaconBlock{
					Slot: 1,
				},
			},
		},
	}})
	require.EqualError(t, err, "no successful submissions before timeout")
}

func TestSubmitProposalSleepy(t *testing.T) {
	ctx := context.Background()

	s, err := newTestService(context.Background(),
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(100*time.Millisecond),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"1": mock.NewSleepyProposalSubmitter(200*time.Millisecond, mock.NewProposalSubmitter()),
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

	err = s.SubmitProposal(ctx, &api.SubmitProposalOpts{Proposal: &api.VersionedSignedProposal{
		Version: spec.DataVersionDeneb,
		Deneb: &apiv1deneb.SignedBlockContents{
			SignedBlock: &deneb.SignedBeaconBlock{
				Message: &deneb.BeaconBlock{
					Slot: 1,
				},
			},
		},
	}})
	require.EqualError(t, err, "no successful submissions before timeout")
}

func TestSubmitProposalSleepySuccess(t *testing.T) {
	ctx := context.Background()

	s, err := newTestService(context.Background(),
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(200*time.Millisecond),
		multinode.WithProcessConcurrency(2),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"1": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"1": mock.NewSleepyProposalSubmitter(100*time.Millisecond, mock.NewProposalSubmitter()),
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

	err = s.SubmitProposal(ctx, &api.SubmitProposalOpts{Proposal: &api.VersionedSignedProposal{
		Version: spec.DataVersionDeneb,
		Deneb: &apiv1deneb.SignedBlockContents{
			SignedBlock: &deneb.SignedBeaconBlock{
				Message: &deneb.BeaconBlock{
					Slot: 1,
				},
			},
		},
	}})
	require.NoError(t, err)
}

func TestSubmitProposalEchoesBuilderURLToEveryNode(t *testing.T) {
	ctx := context.Background()
	builderURL := "https://builder.example/path?x=1"

	tests := []struct {
		name       string
		builderURL string
	}{
		{
			name:       "BuilderURL",
			builderURL: builderURL,
		},
		{
			name: "NoBuilderURL",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := make(chan []string, 2)
			submitters := make(map[string]eth2client.ProposalSubmitter)
			for _, name := range []string{"1", "2"} {
				server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
					switch r.URL.Path {
					case "/eth/v1/node/version":
						_, _ = w.Write([]byte(`{"data":{"version":"test"}}`))
					case "/eth/v1/node/syncing":
						_, _ = w.Write([]byte(`{"data":{"is_syncing":false,"is_optimistic":false,"el_offline":false,"head_slot":"1","sync_distance":"0"}}`))
					case "/eth/v1/config/spec":
						w.WriteHeader(nethttp.StatusNotFound)
					case "/eth/v2/beacon/blocks":
						headers <- r.Header.Values("Eth-Builder-Url")
					default:
						w.WriteHeader(nethttp.StatusNotFound)
					}
				}))
				t.Cleanup(server.Close)
				client, err := eth2http.New(ctx,
					eth2http.WithLogLevel(zerolog.Disabled),
					eth2http.WithAddress(server.URL),
					eth2http.WithTimeout(time.Second),
				)
				require.NoError(t, err)
				submitter, isSubmitter := client.(eth2client.ProposalSubmitter)
				require.True(t, isSubmitter)
				submitters[name] = submitter
			}

			s, err := newTestService(ctx,
				multinode.WithLogLevel(zerolog.Disabled),
				multinode.WithTimeout(time.Second),
				multinode.WithProcessConcurrency(2),
				multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{"1": mock.NewAttestationsSubmitter()}),
				multinode.WithProposalSubmitters(submitters),
				multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{"1": mock.NewBeaconCommitteeSubscriptionsSubmitter()}),
				multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{"1": mock.NewAggregateAttestationsSubmitter()}),
				multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{"1": mock.NewProposalPreparationsSubmitter()}),
				multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{"1": mock.NewSyncCommitteeMessagesSubmitter()}),
				multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{"1": mock.NewSyncCommitteeSubscriptionsSubmitter()}),
				multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{"1": mock.NewSyncCommitteeContributionsSubmitter()}),
			)
			require.NoError(t, err)

			proposalClient, err := mockconsensusclient.New(ctx)
			require.NoError(t, err)
			includePayload := false
			proposal, err := proposalClient.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, IncludePayload: &includePayload})
			require.NoError(t, err)

			require.NoError(t, s.SubmitProposal(ctx, &api.SubmitProposalOpts{
				Proposal: &api.VersionedSignedProposal{
					Version: spec.DataVersionGloas,
					Gloas:   &gloas.SignedBeaconBlock{Message: proposal.Data.Gloas},
				},
				BuilderURL: test.builderURL,
			}))

			// The submitter returns after the first node accepts, so wait for both.
			expected := []string(nil)
			if test.builderURL != "" {
				expected = []string{test.builderURL}
			}
			for range submitters {
				select {
				case received := <-headers:
					require.Equal(t, expected, received)
				case <-time.After(time.Second):
					require.Fail(t, "proposal not submitted to every node")
				}
			}
		})
	}
}
