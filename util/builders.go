// Copyright © 2022, 2023 Attestant Limited.
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
	"fmt"
	"net/url"
	"sync"

	builder "github.com/attestantio/go-builder-client"
	httpclient "github.com/attestantio/go-builder-client/http"
	"github.com/attestantio/go-eth2-client/metrics"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

var (
	builders   map[string]builder.Service
	buildersMu sync.Mutex
)

// FetchBuilderClient fetches a builder client, instantiating it if required.
func FetchBuilderClient(ctx context.Context, address string, monitor metrics.Service, releaseVersion string) (builder.Service, error) {
	if address == "" {
		return nil, errors.New("no address supplied")
	}

	buildersMu.Lock()
	defer buildersMu.Unlock()
	if builders == nil {
		builders = make(map[string]builder.Service)
	}

	extraHeaders, err := builderClientHeaders(address, releaseVersion)
	if err != nil {
		return nil, err
	}

	client, exists := builders[address]
	if !exists {
		client, err = httpclient.New(ctx,
			httpclient.WithMonitor(monitor),
			httpclient.WithLogLevel(LogLevel(fmt.Sprintf("builderclient.%s", address))),
			httpclient.WithTimeout(Timeout(fmt.Sprintf("builderclient.%s", address))),
			httpclient.WithAddress(address),
			httpclient.WithExtraHeaders(extraHeaders),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to initiate builder client")
		}
		builders[address] = client
	}

	return client, nil
}

func builderClientHeaders(address string, releaseVersion string) (map[string]string, error) {
	// Vouch version for initial header.
	extraHeaders := map[string]string{
		"User-Agent": fmt.Sprintf("Vouch/%s", releaseVersion),
	}

	// Generic user-defined headers for all clients.
	for k, v := range viper.GetStringMapString("builderclient.headers.all") {
		extraHeaders[k] = v
	}

	parsedAddress, err := url.Parse(address)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse address")
	}

	// Specific headers for this client.
	for k, v := range viper.GetStringMapString(fmt.Sprintf("builderclient.headers.%s", parsedAddress.Host)) {
		extraHeaders[k] = v
	}

	return extraHeaders, nil
}
