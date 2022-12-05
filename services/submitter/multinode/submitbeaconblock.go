// Copyright © 2020 - 2022 Attestant Limited.
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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/semaphore"
)

// SubmitBeaconBlock submits a beacon block.
func (s *Service) SubmitBeaconBlock(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
	ctx, span := otel.Tracer("attestantio.vouch.service.submitter.multinode").Start(ctx, "SubmitBeaconBlock", trace.WithAttributes(
		attribute.String("strategy", "multinode"),
	))
	defer span.End()

	if block == nil {
		return errors.New("no beacon block supplied")
	}

	var err error
	sem := semaphore.NewWeighted(s.processConcurrency)
	w := sync.NewCond(&sync.Mutex{})
	w.L.Lock()
	for name, submitter := range s.beaconBlockSubmitters {
		go s.submitBeaconBlock(ctx, sem, w, name, block, submitter)
	}
	// Also set a timeout condition, in case no submitters return.
	go func(s *Service, w *sync.Cond) {
		time.Sleep(s.timeout)
		err = errors.New("no successful submissions before timeout")
		w.Signal()
	}(s, w)
	w.Wait()
	w.L.Unlock()

	return err
}

// submitBeaconBlock carries out the internal work of submitting beacon blocks.
// skipcq: RVV-B0001
func (s *Service) submitBeaconBlock(ctx context.Context,
	sem *semaphore.Weighted,
	w *sync.Cond,
	name string,
	block *spec.VersionedSignedBeaconBlock,
	submitter eth2client.BeaconBlockSubmitter,
) {
	ctx, span := otel.Tracer("attestantio.vouch.service.submitter.multinode").Start(ctx, "submitBeaconBlock", trace.WithAttributes(
		attribute.String("server", name),
	))
	defer span.End()

	slot, err := block.Slot()
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain slot")
		return
	}
	log := log.With().Str("beacon_node_address", name).Uint64("slot", uint64(slot)).Logger()
	if err := sem.Acquire(ctx, 1); err != nil {
		log.Error().Err(err).Msg("Failed to acquire semaphore")
		return
	}
	defer sem.Release(1)

	_, address := s.serviceInfo(ctx, submitter)
	started := time.Now()
	err = submitter.SubmitBeaconBlock(ctx, block)

	s.clientMonitor.ClientOperation(address, "submit beacon block", err == nil, time.Since(started))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to submit beacon block")
		return
	}

	w.Signal()
	log.Trace().Msg("Submitted beacon block")
}
