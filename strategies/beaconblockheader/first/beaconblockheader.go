// Copyright © 2024 Attestant Limited.
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

package first

import (
	"context"
	"net/http"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	clientprometheus "github.com/attestantio/vouch/services/metrics/prometheus"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type beaconBlockHeaderResp struct {
	provider string
	response *api.Response[*apiv1.BeaconBlockHeader]
}

// BeaconBlockHeader provides the beacon block header from a number of beacon nodes.
func (s *Service) BeaconBlockHeader(ctx context.Context,
	opts *api.BeaconBlockHeaderOpts,
) (
	*api.Response[*apiv1.BeaconBlockHeader],
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockheaders.first").Start(ctx, "BeaconBlockHeaders", trace.WithAttributes(
		attribute.String("blockid", opts.Block),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, s.log, "strategy_id")

	// We create a cancelable context with a timeout.  When a provider responds we cancel the context to cancel the other requests.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	respCh := make(chan *beaconBlockHeaderResp, 1)
	for name, provider := range s.beaconBlockHeadersProviders {
		go func(ctx context.Context,
			name string,
			provider eth2client.BeaconBlockHeadersProvider,
			ch chan *beaconBlockHeaderResp,
		) {
			log := log.With().Str("provider", name).Str("block_id", opts.Block).Logger()

			response, err := provider.BeaconBlockHeader(ctx, opts)
			clientprometheus.MonitorClientOperation(name, "beacon block header", err == nil, time.Since(started))
			if err != nil {
				if errors.Is(err, context.Canceled) {
					// The context has been canceled, due to another provider getting there first.  This is fine.
					return
				}
				var apiErr *api.Error
				if errors.As(err, &apiErr) {
					switch apiErr.StatusCode {
					case http.StatusNotFound:
						// The provider doesn't have the data.  This is fine.
						return
					case http.StatusServiceUnavailable:
						// The provider isn't able to provide us with data.  This is fine.
						return
					}
				}
				log.Debug().Dur("elapsed", time.Since(started)).Err(err).Msg("Failed to obtain beacon block header")

				return
			}
			log.Trace().Str("provider", name).Dur("elapsed", time.Since(started)).Msg("Obtained beacon block header")

			ch <- &beaconBlockHeaderResp{
				provider: name,
				response: response,
			}
		}(ctx, name, provider, respCh)
	}

	select {
	case <-ctx.Done():
		cancel()
		log.Warn().Msg("Failed to obtain beacon block header before timeout")
		return nil, errors.New("failed to obtain beacon block header before timeout")
	case resp := <-respCh:
		cancel()
		clientprometheus.MonitorStrategyOperation("first", resp.provider, "beacon block header", time.Since(started))
		return resp.response, nil
	}
}
