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

package main

import (
	"context"
	"encoding/binary"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	bitfield "github.com/OffchainLabs/go-bitfield"
	client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1gloas "github.com/attestantio/go-eth2-client/api/v1/gloas"
	mockconsensusclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics/null"
	dynssz "github.com/pk910/dynamic-ssz"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestFetchClientCustomSpecSupport(t *testing.T) {
	ctx := context.Background()
	customSSZ := dynssz.NewDynSsz(map[string]any{
		"SYNC_COMMITTEE_SIZE": uint64(32),
	}, dynssz.WithNoFastSsz())
	block := &gloas.BeaconBlock{
		Slot: 1,
		Body: &gloas.BeaconBlockBody{
			SyncAggregate: &altair.SyncAggregate{
				SyncCommitteeBits: bitfield.Bitvector512{0, 0, 0, 0},
			},
		},
	}
	body, err := customSSZ.MarshalSSZ(block.Body)
	require.NoError(t, err)
	require.EqualValues(t, 336, binary.LittleEndian.Uint32(body[200:204]))
	encoded, err := customSSZ.MarshalSSZ(block)
	require.NoError(t, err)

	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/eth/v1/node/version":
			_, _ = w.Write([]byte(`{"data":{"version":"test"}}`))
		case "/eth/v1/node/syncing":
			_, _ = w.Write([]byte(`{"data":{"is_syncing":false,"is_optimistic":false,"el_offline":false,"head_slot":"1","sync_distance":"0"}}`))
		case "/eth/v1/config/spec":
			_, _ = w.Write([]byte(`{"data":{"SYNC_COMMITTEE_SIZE":"32"}}`))
		case "/eth/v4/validator/blocks/1":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Eth-Consensus-Version", "gloas")
			w.Header().Set("Eth-Execution-Payload-Included", "false")
			_, _ = w.Write(encoded)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(nethttp.StatusNotFound)
		}
	}))
	defer server.Close()

	viper.Set("fetch-client-test-sentinel", "must not leak")
	viper.Set("timeout", "2s")
	viper.Set("eth2client.timeout", "2s")
	viper.Set("eth2client.custom-spec-support", true)
	t.Cleanup(func() {
		viper.Reset()
		require.Nil(t, viper.Get("fetch-client-test-sentinel"))
		knownClientsMu.Lock()
		delete(knownClients, server.URL)
		knownClientsMu.Unlock()
	})

	service, err := fetchClient(ctx, null.New(), server.URL)
	require.NoError(t, err)

	includePayload := false
	response, err := service.(client.EPBSProposalProvider).EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot:           1,
		IncludePayload: &includePayload,
	})
	require.NoError(t, err)
	require.Equal(t, spec.DataVersionGloas, response.Data.Version)
	require.Equal(t, block.Slot, response.Data.Gloas.Slot)
}

func TestSimpleProposalProviderRejectsZeroFeeRecipient(t *testing.T) {
	ctx := context.Background()
	const address = "http://proposal.test"
	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	proposalClient.EPBSProposalFunc = func(context.Context, *api.EPBSProposalOpts) (*api.Response[*api.VersionedEPBSProposal], error) {
		return &api.Response[*api.VersionedEPBSProposal]{
			Data: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
				GloasContents: &apiv1gloas.BlockContents{Block: &gloas.BeaconBlock{Body: &gloas.BeaconBlockBody{
					SignedExecutionPayloadBid: &gloas.SignedExecutionPayloadBid{Message: &gloas.ExecutionPayloadBid{
						FeeRecipient: bellatrix.ExecutionAddress{},
					}},
				}}},
			},
		}, nil
	}
	viper.Set("strategies.beaconblockproposal.style", "simple")
	viper.Set("strategies.beaconblockproposal.beacon-node-addresses", []string{address})
	viper.Set("strategies.beaconblockproposal.first.timeout", 10*time.Millisecond)
	knownClientsMu.Lock()
	knownClients[address] = proposalClient
	knownClientsMu.Unlock()
	t.Cleanup(func() {
		viper.Reset()
		knownClientsMu.Lock()
		delete(knownClients, address)
		delete(knownClients, "multi:"+address)
		knownClientsMu.Unlock()
	})

	provider, err := selectProposalProvider(ctx, null.New(), nil, nil, nil)
	require.NoError(t, err)
	includePayload := true
	response, err := provider.EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot:           phase0.Slot(1),
		IncludePayload: &includePayload,
	})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
}
