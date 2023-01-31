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
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// AggregateAttestation provides the aggregate attestation from a number of beacon nodes.
func (s *Service) AggregateAttestation(ctx context.Context, slot phase0.Slot, attestationDataRoot phase0.Root) (*phase0.Attestation, error) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.aggregateattestation.first").Start(ctx, "AggregateAttestation", trace.WithAttributes(
		attribute.Int64("slot", int64(slot)),
	))
	defer span.End()

	started := time.Now()
	log := util.LogWithID(ctx, log, "strategy_id")

	// We create a cancelable context with a timeout.  When a provider responds we cancel the context to cancel the other requests.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	respCh := make(chan *phase0.Attestation, 1)
	for name, provider := range s.aggregateAttestationProviders {
		go func(ctx context.Context,
			name string,
			provider eth2client.AggregateAttestationProvider,
			ch chan *phase0.Attestation,
		) {
			log := log.With().Str("provider", name).Uint64("slot", uint64(slot)).Logger()

			aggregate, err := provider.AggregateAttestation(ctx, slot, attestationDataRoot)
			s.clientMonitor.ClientOperation(name, "aggregate attestation", err == nil, time.Since(started))
			if err != nil {
				log.Warn().Err(err).Msg("Failed to obtain aggregate attestation")
				return
			}
			if aggregate == nil {
				log.Warn().Msg("Returned empty aggregate attestation")
				return
			}
			log.Trace().Str("provider", name).Msg("Obtained aggregate attestation")

			ch <- aggregate
		}(ctx, name, provider, respCh)
	}

	select {
	case <-ctx.Done():
		cancel()
		log.Warn().Msg("Failed to obtain aggregate attestation before timeout")
		return nil, errors.New("failed to obtain aggregate attestation before timeout")
	case aggregate := <-respCh:
		cancel()
		return aggregate, nil
	}
}
