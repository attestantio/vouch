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

package first_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	httpclient "github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/vouch/strategies/beaconblockheader/first"
	"github.com/attestantio/vouch/util"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestBeaconBlockHeadersAbsenceWhileANodeIsDown runs the strategy through real go-eth2-client clients. Node "up"
// always reports no block; node "down" stops partway, or is down from the start. Every lookup while it is down must
// report absence: go-eth2-client returns a dial error on the first failed request and "client is not active" after.
func TestBeaconBlockHeadersAbsenceWhileANodeIsDown(t *testing.T) {
	for _, downAtStart := range []bool{false, true} {
		t.Run(fmt.Sprintf("DownAtStart=%v", downAtStart), func(t *testing.T) {
			up := fakeBeaconNode(t)
			down := fakeBeaconNode(t)
			providers := map[string]consensusclient.BeaconBlockHeadersProvider{
				"up": realClient(t, up.URL),
			}
			if downAtStart {
				down.Close()
			}
			providers["down"] = realClient(t, down.URL)
			s, err := first.New(context.Background(),
				first.WithLogLevel(zerolog.Disabled),
				first.WithTimeout(2*time.Second),
				first.WithBeaconBlockHeadersProviders(providers),
			)
			require.NoError(t, err)

			if !downAtStart {
				_, err := s.BeaconBlockHeader(context.Background(), &api.BeaconBlockHeaderOpts{Block: "1"})
				require.True(t, util.IsNotFound(err), "both nodes up: %v", err)
				down.Close()
			}
			for lookup := range 3 {
				_, err := s.BeaconBlockHeader(context.Background(), &api.BeaconBlockHeaderOpts{Block: "1"})
				require.True(t, util.IsNotFound(err), "lookup %d while a node is down: %v", lookup+1, err)
			}
		})
	}
}

// fakeBeaconNode serves the endpoints go-eth2-client needs to mark a node active, and 404 for every header.
func fakeBeaconNode(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/eth/v1/node/syncing":
			_, _ = fmt.Fprint(w, `{"data":{"head_slot":"10","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}`)
		case "/eth/v1/node/version":
			_, _ = fmt.Fprint(w, `{"data":{"version":"test/v1.0.0"}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"code":404,"message":"NOT_FOUND"}`)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func realClient(t *testing.T, address string) consensusclient.BeaconBlockHeadersProvider {
	t.Helper()
	client, err := httpclient.New(context.Background(),
		httpclient.WithAddress(address),
		httpclient.WithAllowDelayedStart(true),
		httpclient.WithTimeout(2*time.Second),
		httpclient.WithLogLevel(zerolog.Disabled),
	)
	require.NoError(t, err)

	return client.(consensusclient.BeaconBlockHeadersProvider)
}
