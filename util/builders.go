// Copyright © 2022 Attestant Limited.
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

package util

import (
	"context"
	"sync"

	builder "github.com/attestantio/go-builder-client"
	httpclient "github.com/attestantio/go-builder-client/http"
	"github.com/attestantio/go-eth2-client/metrics"
	"github.com/pkg/errors"
)

var builders map[string]builder.Service
var buildersMu sync.Mutex

// FetchBuilderClient fetches a builder client, instantiating it if required.
func FetchBuilderClient(ctx context.Context, address string, monitor metrics.Service) (builder.Service, error) {
	if address == "" {
		return nil, errors.New("no address supplied")
	}

	buildersMu.Lock()
	defer buildersMu.Unlock()
	if builders == nil {
		builders = make(map[string]builder.Service)
	}

	var client builder.Service
	var exists bool
	if client, exists = builders[address]; !exists {
		var err error
		client, err = httpclient.New(ctx,
			httpclient.WithMonitor(monitor),
			httpclient.WithLogLevel(LogLevel("builderclient")),
			httpclient.WithTimeout(Timeout("builderclient")),
			httpclient.WithAddress(address))
		if err != nil {
			return nil, errors.Wrap(err, "failed to initiate builder client")
		}
		builders[address] = client
	}
	return client, nil
}
