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

package multinode

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/semaphore"
)

// SubmitAggregateAttestations submits aggregate attestations.
func (s *Service) SubmitAggregateAttestations(ctx context.Context, aggregates []*phase0.SignedAggregateAndProof) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.submitter.multinode").Start(ctx, "SubmitAggregateAttestations", trace.WithAttributes(
		attribute.String("strategy", "multinode"),
	))
	defer span.End()

	if len(aggregates) == 0 {
		return errors.New("no aggregate attestations supplied")
	}

	sem := semaphore.NewWeighted(s.processConcurrency)
	submissionCompleted := &atomic.Bool{}
	w := sync.NewCond(&sync.Mutex{})
	w.L.Lock()
	for name, submitter := range s.aggregateAttestationsSubmitters {
		go s.submitAggregateAttestations(ctx, sem, w, submissionCompleted, name, aggregates, submitter)
	}
	// Also set a timeout condition, in case no submitters return.
	go func(s *Service, w *sync.Cond) {
		time.Sleep(s.timeout)
		w.Signal()
	}(s, w)
	w.Wait()
	w.L.Unlock()

	var err error
	if !submissionCompleted.Load() {
		err = errors.New("no successful submissions before timeout")
	}

	return err
}

// submitAggregateAttestations carries out the internal work of submitting aggregate attestations.
// skipcq: RVV-B0001
func (s *Service) submitAggregateAttestations(ctx context.Context,
	sem *semaphore.Weighted,
	w *sync.Cond,
	submissionCompleted *atomic.Bool,
	name string,
	aggregates []*phase0.SignedAggregateAndProof,
	submitter eth2client.AggregateAttestationsSubmitter,
) {
	log := s.log.With().Str("beacon_node_address", name).Uint64("slot", uint64(aggregates[0].Message.Aggregate.Data.Slot)).Logger()
	if err := sem.Acquire(ctx, 1); err != nil {
		log.Error().Err(err).Msg("Failed to acquire semaphore")
		return
	}
	defer sem.Release(1)

	_, address := s.serviceInfo(ctx, submitter)
	started := time.Now()
	err := submitter.SubmitAggregateAttestations(ctx, aggregates)

	s.clientMonitor.ClientOperation(address, "submit aggregate attestations", err == nil, time.Since(started))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to submit aggregate attestations")
		return
	}

	submissionCompleted.Store(true)
	w.Signal()
	log.Trace().Msg("Submitted aggregate attestations")
}
