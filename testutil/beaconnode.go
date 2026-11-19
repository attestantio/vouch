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

package testutil

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// NoBlockBeaconNode serves the endpoints go-eth2-client needs to mark a node synced, and 404 for every header.  Any
// other path fails with 500, so only a header lookup can report absence.
func NoBlockBeaconNode(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/eth/v1/node/syncing":
			_, _ = fmt.Fprint(w, `{"data":{"head_slot":"10","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}`)
		case r.URL.Path == "/eth/v1/node/version":
			_, _ = fmt.Fprint(w, `{"data":{"version":"test/v1.0.0"}}`)
		case strings.HasPrefix(r.URL.Path, "/eth/v1/beacon/headers/"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"code":404,"message":"NOT_FOUND"}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(server.Close)

	return server
}
