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

package util_test

import (
	"context"
	"testing"
	"time"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	httpclient "github.com/attestantio/go-eth2-client/http"
	multiclient "github.com/attestantio/go-eth2-client/multi"
	"github.com/attestantio/vouch/testutil"
	"github.com/attestantio/vouch/util"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestIsNotFoundThroughMultiClient checks that a header 404 reaches the caller of the multi client, which the simple
// beacon block header strategy uses, as a 404.
func TestIsNotFoundThroughMultiClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clients := make([]consensusclient.Service, 0, 2)
	for range 2 {
		client, err := httpclient.New(ctx,
			httpclient.WithAddress(testutil.NoBlockBeaconNode(t).URL),
			httpclient.WithTimeout(2*time.Second),
			httpclient.WithLogLevel(zerolog.Disabled),
		)
		require.NoError(t, err)
		clients = append(clients, client)
	}
	multi, err := multiclient.New(ctx,
		multiclient.WithClients(clients),
		multiclient.WithLogLevel(zerolog.Disabled),
	)
	require.NoError(t, err)

	_, err = multi.(consensusclient.BeaconBlockHeadersProvider).BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{Block: "1"})
	require.True(t, util.IsNotFound(err), "%v", err)
}
