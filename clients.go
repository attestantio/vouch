// Copyright © 2020 - 2023 Attestant Limited.
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

	eth2client "github.com/attestantio/go-eth2-client"
	httpclient "github.com/attestantio/go-eth2-client/http"
	multiclient "github.com/attestantio/go-eth2-client/multi"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
)

var (
	knownClients   = make(map[string]eth2client.Service)
	knownClientsMu sync.Mutex
)

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
			httpclient.WithExtraHeaders(map[string]string{
				"User-Agent": fmt.Sprintf("Vouch/%s", ReleaseVersion),
			}),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to initiate consensus client")
		}

		knownClientsMu.Lock()
		knownClients[address] = client
		knownClientsMu.Unlock()
	}
	return client, nil
}

// fetchMulticlient fetches a multiclient service, instantiating it if required.
func fetchMultiClient(ctx context.Context, monitor metrics.Service, addresses []string) (eth2client.Service, error) {
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
			multiclient.WithClients(clients),
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
