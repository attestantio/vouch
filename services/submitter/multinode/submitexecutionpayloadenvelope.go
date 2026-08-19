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
	"strconv"
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
	beaconBlockRoot := "<unknown>"
	if opts.SignedExecutionPayloadEnvelope != nil {
		if root, err := opts.SignedExecutionPayloadEnvelope.BeaconBlockRoot(); err == nil {
			beaconBlockRoot = root.String()
		}
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)

	sem := semaphore.NewWeighted(s.processConcurrency)
	results := make(chan error, len(s.executionPayloadEnvelopeSubmitters))
	for name, submitter := range s.executionPayloadEnvelopeSubmitters {
		go s.submitExecutionPayloadEnvelope(ctx, sem, results, name, beaconBlockRoot, opts, submitter)
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
				s.log.Trace().Str("beacon_block_root", beaconBlockRoot).Bool("any_provider_succeeded", true).Msg("Execution payload envelope submission completed")

				return nil
			}
			submissionErrors = append(submissionErrors, err)
		case <-ctx.Done():
			cancel()
			submissionErrors = append(submissionErrors, errors.New("no successful submissions before timeout"))
			s.log.Warn().Str("beacon_block_root", beaconBlockRoot).Bool("any_provider_succeeded", false).Msg("Execution payload envelope submission completed")

			return submitter.NewSubmissionError(submissionErrors...)
		}
	}

	cancel()
	s.log.Warn().Str("beacon_block_root", beaconBlockRoot).Bool("any_provider_succeeded", false).Msg("Execution payload envelope submission completed")

	return submitter.NewSubmissionError(submissionErrors...)
}

func (s *Service) submitExecutionPayloadEnvelope(ctx context.Context,
	sem *semaphore.Weighted,
	results chan<- error,
	name string,
	beaconBlockRoot string,
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

	address := name
	if service, isService := submitter.(eth2client.Service); isService {
		address = service.Address()
	}
	log := s.log.With().Str("provider", name).Str("beacon_block_root", beaconBlockRoot).Logger()
	started := time.Now()
	err := submitter.SubmitExecutionPayloadEnvelope(ctx, opts)
	elapsed := time.Since(started)
	s.clientMonitor.ClientOperation(address, "submit execution payload envelope", err == nil, elapsed)
	if err != nil {
		status := "failed"
		var apiErr *api.Error
		if errors.As(err, &apiErr) {
			status = strconv.Itoa(apiErr.StatusCode)
		}
		log.Warn().Err(err).Str("status", status).Dur("elapsed", elapsed).Msg("Execution payload envelope provider submission completed")
		results <- fmt.Errorf("%s: %w", name, err)
		return
	}

	results <- nil
	log.Trace().Str("status", "succeeded").Dur("elapsed", elapsed).Msg("Execution payload envelope provider submission completed")
}
