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
	"encoding/json"
	"fmt"
	"io"
	nethttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	bitfield "github.com/OffchainLabs/go-bitfield"
	client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	apiv1gloas "github.com/attestantio/go-eth2-client/api/v1/gloas"
	httpclient "github.com/attestantio/go-eth2-client/http"
	mockconsensusclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/payloadattester"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/attestantio/vouch/testutil"
	dynssz "github.com/pk910/dynamic-ssz"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
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
		BuilderConfig:  &gloas.BuilderConfig{Builders: []*gloas.BuilderEntry{}},
	})
	require.NoError(t, err)
	require.Equal(t, spec.DataVersionGloas, response.Data.Version)
	require.Equal(t, block.Slot, response.Data.Gloas.Slot)
}

func TestFetchClientDoesNotLogEPBSBuilderAuth(t *testing.T) {
	ctx := context.Background()
	var proposalRequests atomic.Int64
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/eth/v1/node/version":
			_, _ = w.Write([]byte(`{"data":{"version":"test"}}`))
		case "/eth/v1/node/syncing":
			_, _ = w.Write([]byte(`{"data":{"is_syncing":false,"is_optimistic":false,"el_offline":false,"head_slot":"1","sync_distance":"0"}}`))
		case "/eth/v4/validator/blocks/1":
			if r.Method != nethttp.MethodPost {
				t.Errorf("unexpected method %s", r.Method)
				w.WriteHeader(nethttp.StatusMethodNotAllowed)
				return
			}
			proposalRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(nethttp.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"code":500,"message":"failed"}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(nethttp.StatusNotFound)
		}
	}))
	defer server.Close()

	viper.Set("eth2client.log-level", "trace")
	viper.Set("eth2client.timeout", "2s")
	t.Cleanup(func() {
		viper.Reset()
		knownClientsMu.Lock()
		delete(knownClients, server.URL)
		knownClientsMu.Unlock()
	})
	capture := logger.NewLogCapture()
	service, err := fetchClient(ctx, null.New(), server.URL)
	require.NoError(t, err)
	includePayload := false
	sensitive := "private-auth-value"
	_, err = service.(client.EPBSProposalProvider).EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot:           1,
		IncludePayload: &includePayload,
		BuilderConfig: &gloas.BuilderConfig{Builders: []*gloas.BuilderEntry{{
			URL: []byte("https://builder.example"),
			Auth: &gloas.SignedBuilderRequestAuth{
				Message: &gloas.BuilderRequestAuth{Data: []byte(sensitive), Slot: 1},
			},
		}}},
	})
	require.Error(t, err)
	require.Equal(t, int64(1), proposalRequests.Load())
	require.NotEmpty(t, capture.Entries())
	require.NotContains(t, fmt.Sprint(capture.Entries()), sensitive)
}

func TestEPBSProposalBuilderConfigTransports(t *testing.T) {
	ctx := context.Background()
	includePayload := false
	config := &gloas.BuilderConfig{
		MinBid:             12,
		BuilderBoostFactor: 100,
		Builders: []*gloas.BuilderEntry{{
			URL: []byte("https://builder.example"),
			Auth: &gloas.SignedBuilderRequestAuth{
				Message:   &gloas.BuilderRequestAuth{Data: []byte{0x12, 0x34}, Slot: 1},
				Signature: phase0.BLSSignature{0x56},
			},
			BuilderPubkeys:      []phase0.BLSPubKey{{0x78}},
			MaxExecutionPayment: 90,
			MinBid:              11,
			BuilderBoostFactor:  80,
		}},
	}
	opts := &api.EPBSProposalOpts{
		Slot:           1,
		IncludePayload: &includePayload,
		BuilderConfig:  config,
	}
	responseClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	response, err := responseClient.EPBSProposal(ctx, opts)
	require.NoError(t, err)
	response.Data.Gloas.Body.SignedExecutionPayloadBid.Message.Value = config.MinBid

	tests := []struct {
		name        string
		enforceJSON bool
		contentType string
	}{
		{name: "JSON", enforceJSON: true, contentType: "application/json"},
		{name: "SSZ", contentType: "application/octet-stream"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var received *gloas.BuilderConfig
			server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
				switch r.URL.Path {
				case "/eth/v1/node/version":
					_, _ = w.Write([]byte(`{"data":{"version":"test"}}`))
				case "/eth/v1/node/syncing":
					_, _ = w.Write([]byte(`{"data":{"is_syncing":false,"is_optimistic":false,"el_offline":false,"head_slot":"1","sync_distance":"0"}}`))
				case "/eth/v4/validator/blocks/1":
					require.Equal(t, test.contentType, r.Header.Get("Content-Type"))
					received = new(gloas.BuilderConfig)
					if test.enforceJSON {
						require.NoError(t, json.NewDecoder(r.Body).Decode(received))
						data, err := response.Data.Gloas.MarshalJSON()
						require.NoError(t, err)
						w.Header().Set("Content-Type", "application/json")
						w.Header().Set("Eth-Consensus-Version", "gloas")
						_, _ = w.Write([]byte(`{"execution_payload_included":false,"data":`))
						_, _ = w.Write(data)
						_, _ = w.Write([]byte(`}`))
					} else {
						data, err := io.ReadAll(r.Body)
						require.NoError(t, err)
						require.NoError(t, received.UnmarshalSSZ(data))
						responseData, err := response.Data.Gloas.MarshalSSZ()
						require.NoError(t, err)
						w.Header().Set("Content-Type", "application/octet-stream")
						w.Header().Set("Eth-Consensus-Version", "gloas")
						w.Header().Set("Eth-Execution-Payload-Included", "false")
						_, _ = w.Write(responseData)
					}
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(nethttp.StatusNotFound)
				}
			}))
			defer server.Close()

			service, err := httpclient.New(ctx,
				httpclient.WithAddress(server.URL),
				httpclient.WithTimeout(2*time.Second),
				httpclient.WithEnforceJSON(test.enforceJSON),
				httpclient.WithLogLevel(zerolog.Disabled),
			)
			require.NoError(t, err)
			proposalResponse, err := service.(client.EPBSProposalProvider).EPBSProposal(ctx, opts)
			require.NoError(t, err)
			require.Equal(t, config, received)
			require.Equal(t, phase0.Slot(1), proposalResponse.Data.Gloas.Slot)
		})
	}
}

func TestPayloadAttesterUsesConfiguredPayloadAttestationDataProviders(t *testing.T) {
	ctx := context.Background()
	var configuredRequests atomic.Int64
	var globalRequests atomic.Int64
	newServer := func(requests *atomic.Int64) *httptest.Server {
		return httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			switch r.URL.Path {
			case "/eth/v1/node/version":
				_, _ = w.Write([]byte(`{"data":{"version":"test"}}`))
			case "/eth/v1/node/syncing":
				_, _ = w.Write([]byte(`{"data":{"is_syncing":false,"is_optimistic":false,"el_offline":false,"head_slot":"12","sync_distance":"0"}}`))
			case "/eth/v1/validator/payload_attestation_data":
				if r.URL.Query().Get("slot") != "12" {
					t.Errorf("unexpected slot %q", r.URL.Query().Get("slot"))
				}
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Eth-Consensus-Version", "gloas")
				_, _ = w.Write([]byte(`{"version":"gloas","data":{"beacon_block_root":"0x0100000000000000000000000000000000000000000000000000000000000000","slot":"12","payload_present":true,"blob_data_available":true}}`))
			default:
				t.Errorf("unexpected request %s", r.URL.Path)
				w.WriteHeader(nethttp.StatusNotFound)
			}
		}))
	}
	configuredServer := newServer(&configuredRequests)
	defer configuredServer.Close()
	globalServer := newServer(&globalRequests)
	defer globalServer.Close()

	viper.Set("timeout", time.Second)
	viper.Set("beacon-node-addresses", []string{globalServer.URL})
	viper.Set("strategies.payloadattestationdata.beacon-node-addresses", []string{configuredServer.URL})
	t.Cleanup(func() {
		viper.Reset()
		knownClientsMu.Lock()
		delete(knownClients, configuredServer.URL)
		delete(knownClients, globalServer.URL)
		delete(knownClients, "multi:"+configuredServer.URL)
		knownClientsMu.Unlock()
	})
	service, err := startPayloadAttester(ctx, null.New(), &payloadAttestationDataSigner{}, &payloadAttestationMessagesSubmitter{})
	require.NoError(t, err)
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 1})
	duty.SetAccount(1, accounts[1])

	_, err = service.Attest(ctx, duty)
	require.NoError(t, err)
	require.Equal(t, int64(1), configuredRequests.Load())
	require.Zero(t, globalRequests.Load())
}

func TestFirstPayloadAttestationDataStrategyRejectsInvalidResponses(t *testing.T) {
	ctx := context.Background()
	invalidAddress := "http://payload-data-invalid.test"
	validAddress := "http://payload-data-valid.test"
	invalid, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	invalid.PayloadAttestationDataFunc = func(context.Context, *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
		return &api.Response[*spec.VersionedPayloadAttestationData]{}, nil
	}
	valid, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	valid.PayloadAttestationDataFunc = func(_ context.Context, opts *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
		return &api.Response[*spec.VersionedPayloadAttestationData]{
			Data: &spec.VersionedPayloadAttestationData{
				Version: spec.DataVersionGloas,
				Gloas:   &gloas.PayloadAttestationData{Slot: opts.Slot},
			},
		}, nil
	}
	viper.Set("strategies.payloadattestationdata.style", "first")
	viper.Set("strategies.payloadattestationdata.first.timeout", time.Second)
	viper.Set("strategies.payloadattestationdata.first.beacon-node-addresses", []string{invalidAddress, validAddress})
	knownClientsMu.Lock()
	knownClients[invalidAddress] = invalid
	knownClients[validAddress] = valid
	knownClientsMu.Unlock()
	t.Cleanup(func() {
		viper.Reset()
		knownClientsMu.Lock()
		delete(knownClients, invalidAddress)
		delete(knownClients, validAddress)
		knownClientsMu.Unlock()
	})

	provider, err := selectPayloadAttestationDataProvider(ctx, null.New())
	require.NoError(t, err)
	response, err := provider.PayloadAttestationData(ctx, &api.PayloadAttestationDataOpts{Slot: 12})
	require.NoError(t, err)
	require.NotNil(t, response.Data)
	require.Equal(t, phase0.Slot(12), response.Data.Gloas.Slot)
}

type payloadAttestationDataSigner struct{}

func (*payloadAttestationDataSigner) SignPayloadAttestationData(_ context.Context, accounts []e2wtypes.Account, _ *gloas.PayloadAttestationData) ([]phase0.BLSSignature, error) {
	return make([]phase0.BLSSignature, len(accounts)), nil
}

type payloadAttestationMessagesSubmitter struct{}

func (*payloadAttestationMessagesSubmitter) SubmitPayloadAttestationMessages(_ context.Context, _ *api.SubmitPayloadAttestationMessagesOpts) error {
	return nil
}

func TestSimpleProposalProviderAcceptsUnknownValue(t *testing.T) {
	ctx := context.Background()
	const address = "http://proposal-unknown.test"
	proposal := &api.VersionedEPBSProposal{
		Version:                  spec.DataVersionGloas,
		ExecutionPayloadIncluded: true,
		GloasContents: &apiv1gloas.BlockContents{Block: &gloas.BeaconBlock{Body: &gloas.BeaconBlockBody{
			SignedExecutionPayloadBid: &gloas.SignedExecutionPayloadBid{Message: &gloas.ExecutionPayloadBid{
				BuilderIndex: gloas.BuilderIndex(^uint64(0)),
				FeeRecipient: bellatrix.ExecutionAddress{0x01},
			}},
		}}},
	}
	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	proposalClient.EPBSProposalFunc = func(context.Context, *api.EPBSProposalOpts) (*api.Response[*api.VersionedEPBSProposal], error) {
		return &api.Response[*api.VersionedEPBSProposal]{Data: proposal}, nil
	}
	viper.Set("strategies.beaconblockproposal.style", "simple")
	viper.Set("strategies.beaconblockproposal.beacon-node-addresses", []string{address})
	viper.Set("strategies.beaconblockproposal.first.timeout", time.Second)
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

	provider, err := selectProposalProvider(ctx, null.New(), nil, nil, nil, nil)
	require.NoError(t, err)
	includePayload := true
	response, err := provider.EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot:           phase0.Slot(1),
		IncludePayload: &includePayload,
	})
	require.NoError(t, err)
	require.Same(t, proposal, response.Data)
	require.Nil(t, response.Data.ExecutionValue)
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
						BuilderIndex: gloas.BuilderIndex(^uint64(0)),
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

	provider, err := selectProposalProvider(ctx, null.New(), nil, nil, nil, nil)
	require.NoError(t, err)
	includePayload := true
	response, err := provider.EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot:           phase0.Slot(1),
		IncludePayload: &includePayload,
	})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
}
