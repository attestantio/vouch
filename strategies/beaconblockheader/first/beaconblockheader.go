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
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/vouch/util"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type beaconBlockHeaderResp struct {
	provider string
	response *api.Response[*apiv1.BeaconBlockHeader]
	err      error
}

// ErrBeaconBlockHeaderTimeout indicates that the header could not be obtained before the deadline.
var ErrBeaconBlockHeaderTimeout = errors.New("failed to obtain beacon block header before timeout")

// BeaconBlockHeader provides the beacon block header from a number of beacon nodes.
// If at least one beacon node returns 404 and every other node returned 404 or was unreachable, the error wraps that 404,
// so callers can tell definitive absence from failure.  A timeout or any other error from a reachable node means no 404
// is wrapped.
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
			respCh <- s.fetchHeader(ctx, log, started, name, provider, opts)
		}(name, provider)
	}

	// Unreachable nodes abstain: the request never reached them, so they say nothing about the block.
	var notFound, unreachableErrors, providerErrors []error
	for len(notFound)+len(unreachableErrors)+len(providerErrors) < len(s.beaconBlockHeadersProviders) {
		var resp *beaconBlockHeaderResp
		select {
		case resp = <-respCh:
		case <-ctx.Done():
			// Use answers that have already arrived; abandon providers still running.
			select {
			case resp = <-respCh:
			default:
				return nil, contextError(ctx, log, slices.Concat(providerErrors, unreachableErrors))
			}
		}
		switch {
		case resp.err == nil:
			s.clientMonitor.StrategyOperation("first", resp.provider, "beacon block header", time.Since(started))

			return resp.response, nil
		case util.IsNotFound(resp.err):
			notFound = append(notFound, resp.err)
		case unreachable(resp.err):
			unreachableErrors = append(unreachableErrors, fmt.Errorf("%s: %w", resp.provider, resp.err))
		default:
			providerErrors = append(providerErrors, fmt.Errorf("%s: %w", resp.provider, resp.err))
		}
	}
	if len(providerErrors) == 0 && len(notFound) > 0 {
		return nil, fmt.Errorf("no reachable beacon node has the beacon block header: %w", notFound[0])
	}
	// Never wrap the 404s here: callers read a wrapped 404 as proof that no block exists.
	failures := slices.Concat(providerErrors, unreachableErrors)
	if ctx.Err() != nil {
		// The last answer raced the strategy's own deadline; report that deadline.
		return nil, contextError(ctx, log, failures)
	}

	// A node's own deadline is that node's error; only contextError reports the strategy's timeout.
	return nil, fmt.Errorf("failed to obtain beacon block header: %w", errors.Join(failures...))
}

// unreachable is true when a request failed while connecting to the node, other than by timing out.
func unreachable(err error) bool {
	var opErr *net.OpError

	return errors.As(err, &opErr) && opErr.Op == "dial" && !opErr.Timeout()
}

// contextError maps the end of the strategy's context to the error returned to callers,
// keeping the errors from providers that answered before it ended.
func contextError(ctx context.Context, log zerolog.Logger, providerErrors []error) error {
	err := ctx.Err()
	if errors.Is(err, context.DeadlineExceeded) {
		log.Debug().Msg("Failed to obtain beacon block header before timeout")
		err = ErrBeaconBlockHeaderTimeout
	}
	if len(providerErrors) == 0 {
		return err
	}

	return fmt.Errorf("%w: %w", err, errors.Join(providerErrors...))
}

// fetchHeader obtains the header from one provider and classifies the outcome.
func (s *Service) fetchHeader(ctx context.Context,
	log zerolog.Logger,
	started time.Time,
	name string,
	provider eth2client.BeaconBlockHeadersProvider,
	opts *api.BeaconBlockHeaderOpts,
) *beaconBlockHeaderResp {
	providerLog := log.With().Str("provider", name).Str("block_id", opts.Block).Logger()
	response, err := provider.BeaconBlockHeader(ctx, opts)
	result := &beaconBlockHeaderResp{provider: name, response: response, err: err}
	switch {
	case err != nil:
		if !util.IsNotFound(err) && !errors.Is(err, context.Canceled) {
			providerLog.Debug().Dur("elapsed", time.Since(started)).Err(err).Msg("Failed to obtain beacon block header")
		}
	case response == nil || response.Data == nil:
		result.err = errors.New("beacon node returned no beacon block header")
		providerLog.Debug().Dur("elapsed", time.Since(started)).Err(result.err).Msg("Failed to obtain beacon block header")
	default:
		providerLog.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained beacon block header")
	}
	s.clientMonitor.ClientOperation(name, "beacon block header", result.err == nil, time.Since(started))

	return result
}
