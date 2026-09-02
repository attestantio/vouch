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
	nethttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	mocketh2client "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestMultinodeSubmitterPublishesProposerPreferencesToProposalProviders(t *testing.T) {
	ctx := context.Background()
	var proposalProviderRequests atomic.Int64
	var proposalSubmitterRequests atomic.Int64
	newServer := func(requests *atomic.Int64) *httptest.Server {
		return httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			switch r.URL.Path {
			case "/eth/v1/node/version":
				_, _ = w.Write([]byte(`{"data":{"version":"test"}}`))
			case "/eth/v1/node/syncing":
				_, _ = w.Write([]byte(`{"data":{"is_syncing":false,"is_optimistic":false,"el_offline":false,"head_slot":"1","sync_distance":"0"}}`))
			case "/eth/v1/validator/proposer_preferences":
				require.Equal(t, nethttp.MethodPost, r.Method)
				requests.Add(1)
			default:
				t.Errorf("unexpected request %s", r.URL.Path)
				w.WriteHeader(nethttp.StatusNotFound)
			}
		}))
	}
	proposalProvider := newServer(&proposalProviderRequests)
	defer proposalProvider.Close()
	proposalSubmitter := newServer(&proposalSubmitterRequests)
	defer proposalSubmitter.Close()

	viper.Set("timeout", time.Second)
	viper.Set("eth2client.timeout", time.Second)
	viper.Set("process-concurrency", int64(1))
	viper.Set("beacon-node-addresses", []string{proposalSubmitter.URL})
	viper.Set("submitter.proposal.beacon-node-addresses", []string{proposalSubmitter.URL})
	viper.Set("strategies.beaconblockproposal.beacon-node-addresses", []string{proposalProvider.URL})
	t.Cleanup(func() {
		viper.Reset()
		knownClientsMu.Lock()
		delete(knownClients, proposalProvider.URL)
		delete(knownClients, proposalSubmitter.URL)
		knownClientsMu.Unlock()
	})

	client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	service, err := startMultinodeSubmitter(ctx, null.New(), client)
	require.NoError(t, err)
	preferencesSubmitter, ok := service.(submitter.ProposerPreferencesSubmitter)
	require.True(t, ok)

	outcomes := preferencesSubmitter.SubmitProposerPreferences(ctx, []*gloas.SignedProposerPreferences{{}}, nil)

	require.Equal(t, map[string]error{proposalProvider.URL: nil}, outcomes)
	require.Equal(t, int64(1), proposalProviderRequests.Load())
	require.Zero(t, proposalSubmitterRequests.Load())
}
