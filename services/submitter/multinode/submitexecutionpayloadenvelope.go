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

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/semaphore"
)

// SubmitExecutionPayloadEnvelope submits a signed execution payload envelope.
func (s *Service) SubmitExecutionPayloadEnvelope(ctx context.Context, opts *api.SubmitExecutionPayloadEnvelopeOpts) error {
	ctx, span := otel.Tracer("attestantio.vouch.service.submitter.multinode").Start(ctx, "SubmitExecutionPayloadEnvelope", trace.WithAttributes(
		attribute.String("strategy", "multinode"),
	))
	defer span.End()

	if opts == nil {
		return errors.New("no execution payload envelope supplied")
	}
	if len(s.executionPayloadEnvelopeSubmitters) == 0 {
		return errors.New("no execution payload envelope submitters configured")
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	sem := semaphore.NewWeighted(s.processConcurrency)
	submissionCompleted := make(chan struct{}, 1)
	submissionSucceeded := &atomic.Bool{}
	var wg sync.WaitGroup
	for name, submitter := range s.executionPayloadEnvelopeSubmitters {
		wg.Go(func() {
			s.submitExecutionPayloadEnvelope(ctx, sem, submissionCompleted, submissionSucceeded, name, opts, submitter)
		})
	}
	// Release the timeout context once every submission has finished, rather than as soon as
	// the first one succeeds, so that one node's success does not abort the others' in-flight
	// submissions.
	go func() {
		wg.Wait()
		cancel()
	}()

	select {
	case <-submissionCompleted:
	case <-ctx.Done():
	}

	// The context is released once every submission has finished, so both cases above can be
	// ready at once and select picks between them at random.  Consult the success flag rather
	// than the chosen case, otherwise a successful submission can report a timeout.
	if !submissionSucceeded.Load() {
		return errors.New("no successful submissions before timeout")
	}

	return nil
}

func (s *Service) submitExecutionPayloadEnvelope(ctx context.Context,
	sem *semaphore.Weighted,
	submissionCompleted chan<- struct{},
	submissionSucceeded *atomic.Bool,
	name string,
	opts *api.SubmitExecutionPayloadEnvelopeOpts,
	submitter eth2client.ExecutionPayloadEnvelopeSubmitter,
) {
	ctx, span := otel.Tracer("attestantio.vouch.service.submitter.multinode").Start(ctx, "submitExecutionPayloadEnvelope", trace.WithAttributes(
		attribute.String("server", name),
	))
	defer span.End()

	if err := sem.Acquire(ctx, 1); err != nil {
		s.log.Error().Err(err).Msg("Failed to acquire semaphore")
		return
	}
	defer sem.Release(1)

	address := "<unknown>"
	if service, isService := submitter.(eth2client.Service); isService {
		address = service.Address()
	}
	started := time.Now()
	err := submitter.SubmitExecutionPayloadEnvelope(ctx, opts)
	s.clientMonitor.ClientOperation(address, "submit execution payload envelope", err == nil, time.Since(started))
	if err != nil {
		s.log.Warn().Err(err).Msg("Failed to submit execution payload envelope")
		return
	}

	submissionSucceeded.Store(true)
	select {
	case submissionCompleted <- struct{}{}:
	default:
	}
	s.log.Trace().Msg("Submitted execution payload envelope")
}
