// Copyright © 2026 Attestant Limited.
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

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/semaphore"
)

// SubmitPayloadAttestationMessages submits payload attestation messages to all configured nodes.
func (s *Service) SubmitPayloadAttestationMessages(ctx context.Context, opts *api.SubmitPayloadAttestationMessagesOpts) error {
	ctx, span := otel.Tracer("attestantio.vouch.service.submitter.multinode").Start(ctx, "SubmitPayloadAttestationMessages", trace.WithAttributes(
		attribute.String("strategy", "multinode"),
	))
	defer span.End()

	if opts == nil || len(opts.Messages) == 0 {
		return errors.New("no payload attestation messages supplied")
	}
	if len(s.payloadAttestationMessagesSubmitters) == 0 {
		return errors.New("no payload attestation message submitters configured")
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	sem := semaphore.NewWeighted(s.processConcurrency)
	submissionSucceeded := &atomic.Bool{}
	var wg sync.WaitGroup
	for name, payloadAttestationMessagesSubmitter := range s.payloadAttestationMessagesSubmitters {
		wg.Go(func() {
			s.submitPayloadAttestationMessages(ctx, cancel, sem, submissionSucceeded, name, opts, payloadAttestationMessagesSubmitter)
		})
	}
	completed := make(chan struct{})
	go func() {
		wg.Wait()
		close(completed)
		cancel()
	}()

	select {
	case <-completed:
	case <-ctx.Done():
	}

	if !submissionSucceeded.Load() {
		return errors.New("no successful submissions before timeout")
	}

	return nil
}

func (s *Service) submitPayloadAttestationMessages(ctx context.Context,
	cancel context.CancelFunc,
	sem *semaphore.Weighted,
	submissionSucceeded *atomic.Bool,
	name string,
	opts *api.SubmitPayloadAttestationMessagesOpts,
	payloadAttestationMessagesSubmitter submitter.PayloadAttestationMessagesSubmitter,
) {
	ctx, span := otel.Tracer("attestantio.vouch.service.submitter.multinode").Start(ctx, "submitPayloadAttestationMessages", trace.WithAttributes(
		attribute.String("server", name),
	))
	defer span.End()

	log := s.log.With().Str("beacon_node_address", name).Logger()
	if err := sem.Acquire(ctx, 1); err != nil {
		log.Error().Err(err).Msg("Failed to acquire semaphore")
		return
	}
	defer sem.Release(1)

	_, address := s.serviceInfo(ctx, payloadAttestationMessagesSubmitter)
	started := time.Now()
	err := payloadAttestationMessagesSubmitter.SubmitPayloadAttestationMessages(ctx, opts)
	s.clientMonitor.ClientOperation(address, "submit payload attestation messages", err == nil, time.Since(started))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to submit payload attestation messages")
		return
	}

	if submissionSucceeded.CompareAndSwap(false, true) {
		cancel()
	}
	log.Trace().Msg("Submitted payload attestation messages")
}
