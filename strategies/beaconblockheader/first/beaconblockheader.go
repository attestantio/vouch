// Copyright © 2024 - 2026 Attestant Limited.
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
	stderrors "errors"
	"fmt"
	"net/http"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/vouch/util"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type beaconBlockHeaderResp struct {
	provider string
	response *api.Response[*apiv1.BeaconBlockHeader]
	notFound bool
	err      error
}

// ErrBeaconBlockHeaderNotFound indicates that every provider definitively lacks the requested header.
var ErrBeaconBlockHeaderNotFound = stderrors.New("beacon block header not found")

// ErrBeaconBlockHeaderTimeout indicates that the header could not be obtained before the deadline.
var ErrBeaconBlockHeaderTimeout = stderrors.New("failed to obtain beacon block header before timeout")

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

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	respCh := make(chan *beaconBlockHeaderResp, len(s.beaconBlockHeadersProviders))
	for name, provider := range s.beaconBlockHeadersProviders {
		go func(name string, provider eth2client.BeaconBlockHeadersProvider) {
			providerLog := log.With().Str("provider", name).Str("block_id", opts.Block).Logger()
			response, err := provider.BeaconBlockHeader(ctx, opts)
			s.clientMonitor.ClientOperation(name, "beacon block header", err == nil, time.Since(started))
			result := &beaconBlockHeaderResp{provider: name, response: response, err: err}
			switch {
			case err != nil:
				var apiErr *api.Error
				switch {
				case stderrors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound:
					result.notFound = true
				case !stderrors.Is(err, context.Canceled):
					providerLog.Debug().Dur("elapsed", time.Since(started)).Err(err).Msg("Failed to obtain beacon block header")
				}
			case response == nil || response.Data == nil:
				result.err = stderrors.New("beacon node returned no beacon block header")
				providerLog.Debug().Dur("elapsed", time.Since(started)).Err(result.err).Msg("Failed to obtain beacon block header")
			default:
				providerLog.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained beacon block header")
			}
			respCh <- result
		}(name, provider)
	}

	providerErrors := make([]error, 0, len(s.beaconBlockHeadersProviders))
	notFoundCount := 0
	timedOut := false
	completed := 0
	process := func(resp *beaconBlockHeaderResp) *api.Response[*apiv1.BeaconBlockHeader] {
		completed++
		if resp.err != nil {
			if resp.notFound {
				notFoundCount++
			} else {
				timedOut = timedOut || stderrors.Is(resp.err, context.DeadlineExceeded)
				providerErrors = append(providerErrors, fmt.Errorf("%s: %w", resp.provider, resp.err))
			}
			return nil
		}
		s.clientMonitor.StrategyOperation("first", resp.provider, "beacon block header", time.Since(started))
		return resp.response
	}
	for completed < len(s.beaconBlockHeadersProviders) {
		select {
		case resp := <-respCh:
			if response := process(resp); response != nil {
				return response, nil
			}
		case <-ctx.Done():
			ctxErr := ctx.Err()
			cancel()
			for completed < len(s.beaconBlockHeadersProviders) {
				select {
				case resp := <-respCh:
					if response := process(resp); response != nil {
						return response, nil
					}
				default:
					if stderrors.Is(ctxErr, context.DeadlineExceeded) {
						log.Debug().Msg("Failed to obtain beacon block header before timeout")
						return nil, ErrBeaconBlockHeaderTimeout
					}
					return nil, ctxErr
				}
			}
		}
	}
	if timedOut {
		return nil, ErrBeaconBlockHeaderTimeout
	}
	if notFoundCount == len(s.beaconBlockHeadersProviders) {
		return nil, ErrBeaconBlockHeaderNotFound
	}
	return nil, fmt.Errorf("failed to obtain beacon block header: %w", stderrors.Join(providerErrors...))
}
