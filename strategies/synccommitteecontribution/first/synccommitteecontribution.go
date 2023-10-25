// Copyright © 2021, 2023 Attestant Limited.
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
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// SyncCommitteeContribution provides the sync committee contribution from a number of beacon nodes.
func (s *Service) SyncCommitteeContribution(ctx context.Context,
	opts *api.SyncCommitteeContributionOpts,
) (
	*api.Response[*altair.SyncCommitteeContribution],
	error,
) {
	if opts == nil {
		return nil, errors.New("no options specified")
	}

	ctx, span := otel.Tracer("attestantio.vouch.strategies.synccommitteecontribution.first").Start(ctx, "SyncCommitteeContribution", trace.WithAttributes(
		attribute.Int64("slot", int64(opts.Slot)),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, log, "strategy_id")

	// We create a cancelable context with a timeout.  When a provider responds we cancel the context to cancel the other requests.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	respCh := make(chan *altair.SyncCommitteeContribution, 1)
	for name, provider := range s.syncCommitteeContributionProviders {
		go func(ctx context.Context,
			name string,
			provider eth2client.SyncCommitteeContributionProvider,
			ch chan *altair.SyncCommitteeContribution,
		) {
			log := log.With().Str("provider", name).Uint64("slot", uint64(opts.Slot)).Uint64("subcommittee_index", opts.SubcommitteeIndex).Stringer("beacon_block_root", opts.BeaconBlockRoot).Logger()

			contributionResponse, err := provider.SyncCommitteeContribution(ctx, opts)
			s.clientMonitor.ClientOperation(name, "sync committee contribution", err == nil, time.Since(started))
			if err != nil {
				log.Warn().Dur("elapsed", time.Since(started)).Err(err).Msg("Failed to obtain sync committee contribution")
				return
			}
			contribution := contributionResponse.Data
			log.Trace().Str("provider", name).Dur("elapsed", time.Since(started)).Msg("Obtained sync committee contribution")

			ch <- contribution
		}(ctx, name, provider, respCh)
	}

	select {
	case <-ctx.Done():
		cancel()
		log.Warn().Msg("Failed to obtain sync committee contribution before timeout")
		return nil, errors.New("failed to obtain sync committee contribution before timeout")
	case contribution := <-respCh:
		cancel()
		return &api.Response[*altair.SyncCommitteeContribution]{
			Data:     contribution,
			Metadata: make(map[string]any),
		}, nil
	}
}
