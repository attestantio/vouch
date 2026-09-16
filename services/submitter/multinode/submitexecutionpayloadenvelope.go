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
	"errors"
	"fmt"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/vouch/services/submitter"
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
	results := make(chan error, len(s.executionPayloadEnvelopeSubmitters))
	for name, submitter := range s.executionPayloadEnvelopeSubmitters {
		go s.submitExecutionPayloadEnvelope(ctx, sem, results, name, opts, submitter)
	}

	submissionErrors := make([]error, 0, len(s.executionPayloadEnvelopeSubmitters))
	for completed := range len(s.executionPayloadEnvelopeSubmitters) {
		select {
		case err := <-results:
			if err == nil {
				// Keep the timeout context active until the other nodes finish, so one
				// node's success does not abort their in-flight submissions.
				remaining := len(s.executionPayloadEnvelopeSubmitters) - completed - 1
				go func() {
					for range remaining {
						<-results
					}
					cancel()
				}()
				return nil
			}
			submissionErrors = append(submissionErrors, err)
		case <-ctx.Done():
			cancel()
			submissionErrors = append(submissionErrors, errors.New("no successful submissions before timeout"))
			return submitter.NewSubmissionError(submissionErrors...)
		}
	}

	cancel()
	return submitter.NewSubmissionError(submissionErrors...)
}

func (s *Service) submitExecutionPayloadEnvelope(ctx context.Context,
	sem *semaphore.Weighted,
	results chan<- error,
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
		results <- fmt.Errorf("%s: %w", name, err)
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
		results <- fmt.Errorf("%s: %w", name, err)
		return
	}

	results <- nil
	s.log.Trace().Msg("Submitted execution payload envelope")
}
