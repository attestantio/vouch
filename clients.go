// Copyright © 2020 Attestant Limited.
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
	"sync"

	eth2client "github.com/attestantio/go-eth2-client"
	autoclient "github.com/attestantio/go-eth2-client/auto"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

var clients map[string]eth2client.Service
var clientsMu sync.Mutex

// fetchClient fetches a client service, instantiating it if required.
func fetchClient(ctx context.Context, address string) (eth2client.Service, error) {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	if clients == nil {
		clients = make(map[string]eth2client.Service)
	}

	var client eth2client.Service
	var exists bool
	if client, exists = clients[address]; !exists {
		var err error
		client, err = autoclient.New(ctx,
			autoclient.WithLogLevel(logLevel(viper.GetString("eth2client.log-level"))),
			autoclient.WithTimeout(viper.GetDuration("eth2client.timeout")),
			autoclient.WithAddress(address))
		if err != nil {
			return nil, errors.Wrap(err, "failed to initiate client")
		}
		clients[address] = client
	}
	return client, nil
}
