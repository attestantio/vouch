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
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type signedBeaconBlockResp struct {
	provider string
	response *api.Response[*spec.VersionedSignedBeaconBlock]
}

// SignedBeaconBlock provides the signed beacon block from a number of beacon nodes.
func (s *Service) SignedBeaconBlock(ctx context.Context,
	opts *api.SignedBeaconBlockOpts,
) (
	*api.Response[*spec.VersionedSignedBeaconBlock],
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.signedbeaconblock.first").Start(ctx, "SignedBeaconBlock", trace.WithAttributes(
		attribute.String("blockid", opts.Block),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, s.log, "strategy_id")

	// We create a cancelable context with a timeout.  When a provider responds we cancel the context to cancel the other requests.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	respCh := make(chan *signedBeaconBlockResp, 1)
	for name, provider := range s.signedBeaconBlockProviders {
		go func(ctx context.Context,
			name string,
			provider eth2client.SignedBeaconBlockProvider,
			ch chan *signedBeaconBlockResp,
		) {
			log := log.With().Str("provider", name).Str("block_id", opts.Block).Logger()

			response, err := provider.SignedBeaconBlock(ctx, opts)
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
				s.clientMonitor.ClientOperation(name, "signed beacon block", err == nil, time.Since(started))
				log.Debug().Dur("elapsed", time.Since(started)).Err(err).Msg("Failed to obtain signed beacon block")

				return
			}
			s.clientMonitor.ClientOperation(name, "signed beacon block", err == nil, time.Since(started))
			log.Trace().Str("provider", name).Dur("elapsed", time.Since(started)).Msg("Obtained signed beacon block")

			ch <- &signedBeaconBlockResp{
				provider: name,
				response: response,
			}
		}(ctx, name, provider, respCh)
	}

	select {
	case <-ctx.Done():
		cancel()
		log.Warn().Msg("Failed to obtain signed beacon block before timeout")
		return nil, errors.New("failed to obtain signed beacon block before timeout")
	case resp := <-respCh:
		cancel()
		s.clientMonitor.StrategyOperation("first", resp.provider, "signed beacon block", time.Since(started))
		return resp.response, nil
	}
}
