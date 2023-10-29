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

// AttestationData provides the first attestation data from a number of beacon nodes.
func (s *Service) AttestationData(ctx context.Context,
	opts *api.AttestationDataOpts,
) (
	*api.Response[*phase0.AttestationData],
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.attestationdata.first").Start(ctx, "AttestationData", trace.WithAttributes(
		attribute.Int64("slot", int64(opts.Slot)),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, log, "strategy_id")

	// We create a cancelable context with a timeout.  When a provider responds we cancel the context to cancel the other requests.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	respCh := make(chan *phase0.AttestationData, 1)
	for name, provider := range s.attestationDataProviders {
		go func(ctx context.Context, name string, provider eth2client.AttestationDataProvider, ch chan *phase0.AttestationData) {
			log := log.With().Str("provider", name).Uint64("slot", uint64(opts.Slot)).Logger()

			attestationDataResponse, err := provider.AttestationData(ctx, opts)
			s.clientMonitor.ClientOperation(name, "attestation data", err == nil, time.Since(started))
			if err != nil {
				log.Warn().Dur("elapsed", time.Since(started)).Err(err).Msg("Failed to obtain attestation data")
				return
			}
			attestationData := attestationDataResponse.Data
			log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained attestation data")

			ch <- attestationData
		}(ctx, name, provider, respCh)
	}

	select {
	case <-ctx.Done():
		cancel()
		log.Warn().Msg("Failed to obtain attestation data before timeout")
		return nil, errors.New("failed to obtain attestation data before timeout")
	case attestationData := <-respCh:
		cancel()
		return &api.Response[*phase0.AttestationData]{
			Data:     attestationData,
			Metadata: make(map[string]any),
		}, nil
	}
}
