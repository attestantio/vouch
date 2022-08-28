// Copyright © 2020, 2021 Attestant Limited.
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
	"github.com/attestantio/go-eth2-client/metrics"
	multiclient "github.com/attestantio/go-eth2-client/multi"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

var clients map[string]eth2client.Service
var clientsMu sync.Mutex

// fetchClient fetches a client service, instantiating it if required.
func fetchClient(ctx context.Context, address string) (eth2client.Service, error) {
	if address == "" {
		return nil, errors.New("no address supplied for client")
	}

	clientsMu.Lock()
	defer clientsMu.Unlock()
	if clients == nil {
		clients = make(map[string]eth2client.Service)
	}

	var client eth2client.Service
	var exists bool
	if client, exists = clients[address]; !exists {
		var err error
		client, err = httpclient.New(ctx,
			httpclient.WithLogLevel(util.LogLevel("eth2client")),
			httpclient.WithTimeout(util.Timeout("eth2client")),
			httpclient.WithAddress(address))
		if err != nil {
			return nil, errors.Wrap(err, "failed to initiate consensus client")
		}
		clients[address] = client
	}
	return client, nil
}

// fetchMulticlient fetches a multiclient service, instantiating it if required.
func fetchMultiClient(ctx context.Context, addresses []string) (eth2client.Service, error) {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	if clients == nil {
		clients = make(map[string]eth2client.Service)
	}

	var client eth2client.Service
	var exists bool
	multiID := fmt.Sprintf("multi:%s", strings.Join(addresses, ","))
	if client, exists = clients[multiID]; !exists {
		// The prometheus metrics service requires a client connection, and the client connection
		// requires a prometheus metrics service.  Square the circle by creating a local metrics
		// service if required.
		var monitor metrics.Service
		if viper.Get("metrics.prometheus") != nil {
			monitor = &consensusMonitor{}
		}

		var err error
		client, err = multiclient.New(ctx,
			multiclient.WithMonitor(monitor),
			multiclient.WithLogLevel(util.LogLevel("eth2client")),
			multiclient.WithTimeout(util.Timeout("eth2client")),
			multiclient.WithAddresses(addresses))
		if err != nil {
			return nil, errors.Wrap(err, "failed to initiate multiclient")
		}
		clients[multiID] = client
	}
	return client, nil
}

// consensusMonitor is a monitor for the consensus client.
type consensusMonitor struct{}

// Presenter provides the presenter for the monitor.
func (*consensusMonitor) Presenter() string {
	return "prometheus"
}
