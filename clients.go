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

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	httpclient "github.com/attestantio/go-eth2-client/http"
	multiclient "github.com/attestantio/go-eth2-client/multi"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

var (
	knownClients   = make(map[string]eth2client.Service)
	knownClientsMu sync.Mutex
)

// clientSyncedHandler is called with a consensus client's address when that client becomes
// synced.  It is set after the clients are constructed, and read each time the hook fires.
var clientSyncedHandler atomic.Pointer[func(address string)]

// setClientSyncedHandler sets the function called when a consensus client becomes synced.
//
// http.New checks a client's connection state before it returns, so a client constructed
// before the handler is set becomes synced for the first time with no handler to call, and
// that transition is not reported.  Later transitions, such as a node becoming synced again
// after a restart, are reported.
//
// The client calls its hooks in a goroutine of their own, one per transition, so the handler
// can run concurrently with itself and must be safe to do so.
func setClientSyncedHandler(handler func(address string)) {
	clientSyncedHandler.Store(&handler)
}

// clientHooks are the hooks provided to each consensus client, allowing vouch to react to
// changes in the client's connection state.
//
// The context passed to a hook is not used.  It can be the context of the request that
// triggered the connection state check, which may already be cancelled.
var clientHooks = &httpclient.Hooks{
	OnSynced: func(_ context.Context, s *httpclient.Service) {
		if handler := clientSyncedHandler.Load(); handler != nil && *handler != nil {
			(*handler)(s.Address())
		}
	},
}

// fetchClient fetches a client service, instantiating it if required.
func fetchClient(ctx context.Context, monitor metrics.Service, address string) (eth2client.Service, error) {
	if address == "" {
		return nil, errors.New("no address supplied for client")
	}

	knownClientsMu.Lock()
	client, exists := knownClients[address]
	knownClientsMu.Unlock()

	if !exists {
		var err error
		client, err = httpclient.New(ctx,
			httpclient.WithLogLevel(util.LogLevel(fmt.Sprintf("eth2client.%s", address))),
			httpclient.WithMonitor(monitor),
			httpclient.WithTimeout(util.Timeout(fmt.Sprintf("eth2client.%s", address))),
			httpclient.WithAddress(address),
			httpclient.WithCustomSpecSupport(viper.GetBool("eth2client.custom-spec-support")),
			httpclient.WithAllowDelayedStart(viper.GetBool("eth2client.allow-delayed-start")),
			httpclient.WithExtraHeaders(map[string]string{
				"User-Agent": fmt.Sprintf("Vouch/%s", ReleaseVersion),
			}),
			httpclient.WithReducedMemoryUsage(util.HierarchicalBool("reduced-memory-usage", fmt.Sprintf("eth2client.%s", address))),
			httpclient.WithHooks(clientHooks),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to initiate consensus client")
		}

		knownClientsMu.Lock()
		knownClients[address] = client
		knownClientsMu.Unlock()
		// NodeVersion is cached by go-eth2-client, so this is a startup snapshot.
		if versionProvider, ok := client.(eth2client.NodeVersionProvider); ok {
			go func() {
				queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				response, err := versionProvider.NodeVersion(queryCtx, &api.NodeVersionOpts{})
				if err == nil && response != nil {
					util.RecordBeaconNodeVersion(address, response.Data)
				}
			}()
		}
	}
	return client, nil
}

// fetchMulticlient fetches a multiclient service, instantiating it if required.
func fetchMultiClient(ctx context.Context, monitor metrics.Service, name string, addresses []string) (eth2client.Service, error) {
	if len(addresses) == 0 {
		return nil, errors.New("no addresses supplied for multiclient")
	}

	multiID := fmt.Sprintf("multi:%s", strings.Join(addresses, ","))

	knownClientsMu.Lock()
	client, exists := knownClients[multiID]
	knownClientsMu.Unlock()

	if !exists {
		// Fetch or create the individual clients.
		clients := make([]eth2client.Service, 0, len(addresses))
		for _, address := range addresses {
			client, err := fetchClient(ctx, monitor, address)
			if err != nil {
				log.Error().Err(err).Str("address", address).Msg("Cannot access client for multiclient; dropping from list")
				continue
			}
			clients = append(clients, client)
		}

		var err error
		client, err = multiclient.New(ctx,
			multiclient.WithMonitor(monitor),
			multiclient.WithLogLevel(util.LogLevel("eth2client.multi")),
			multiclient.WithClients(clients),
			multiclient.WithName(name),
			multiclient.WithAllowDelayedStart(viper.GetBool("eth2client.allow-delayed-start")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to initiate multiclient")
		}

		knownClientsMu.Lock()
		knownClients[multiID] = client
		knownClientsMu.Unlock()
	}

	return client, nil
}
