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

package immediate

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
)

// SubmitExecutionPayloadEnvelope submits a signed execution payload envelope.
func (s *Service) SubmitExecutionPayloadEnvelope(ctx context.Context, opts *api.SubmitExecutionPayloadEnvelopeOpts) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.submitter.immediate").Start(ctx, "SubmitExecutionPayloadEnvelope")
	defer span.End()

	if opts == nil {
		return errors.New("no execution payload envelope supplied")
	}
	if s.executionPayloadEnvelopeSubmitter == nil {
		return errors.New("no execution payload envelope submitter configured")
	}

	started := time.Now()
	err := s.executionPayloadEnvelopeSubmitter.SubmitExecutionPayloadEnvelope(ctx, opts)
	if service, isService := s.executionPayloadEnvelopeSubmitter.(eth2client.Service); isService {
		s.clientMonitor.ClientOperation(service.Address(), "submit execution payload envelope", err == nil, time.Since(started))
	} else {
		s.clientMonitor.ClientOperation("<unknown>", "submit execution payload envelope", err == nil, time.Since(started))
	}
	if err != nil {
		return errors.Wrap(err, "failed to submit execution payload envelope")
	}

	return nil
}
