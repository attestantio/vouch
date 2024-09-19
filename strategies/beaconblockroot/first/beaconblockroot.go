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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// BeaconBlockRoot provides the beacon block root from a number of beacon nodes.
func (s *Service) BeaconBlockRoot(ctx context.Context,
	opts *api.BeaconBlockRootOpts,
) (
	*api.Response[*phase0.Root],
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.beaconblockroot.first").Start(ctx, "BeaconBlockRoot", trace.WithAttributes(
		attribute.String("blockid", opts.Block),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, s.log, "strategy_id")

	// We create a cancelable context with a timeout.  When a provider responds we cancel the context to cancel the other requests.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	respCh := make(chan *api.Response[*phase0.Root], 1)
	for name, provider := range s.beaconBlockRootProviders {
		go func(ctx context.Context,
			name string,
			provider eth2client.BeaconBlockRootProvider,
			ch chan *api.Response[*phase0.Root],
		) {
			log := log.With().Str("provider", name).Str("block_id", opts.Block).Logger()

			rootResponse, err := provider.BeaconBlockRoot(ctx, opts)
			s.clientMonitor.ClientOperation(name, "beacon block root", err == nil, time.Since(started))
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					log.Warn().Dur("elapsed", time.Since(started)).Err(err).Msg("Failed to obtain beacon block root")
				}

				return
			}
			log.Trace().Str("provider", name).Dur("elapsed", time.Since(started)).Msg("Obtained beacon block root")

			ch <- rootResponse
		}(ctx, name, provider, respCh)
	}

	select {
	case <-ctx.Done():
		cancel()
		log.Warn().Msg("Failed to obtain beacon block root before timeout")
		return nil, errors.New("failed to obtain beacon block root before timeout")
	case root := <-respCh:
		cancel()
		return root, nil
	}
}
