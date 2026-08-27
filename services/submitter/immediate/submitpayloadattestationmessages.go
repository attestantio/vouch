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

	"github.com/attestantio/go-eth2-client/api"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
)

// SubmitPayloadAttestationMessages submits payload attestation messages.
func (s *Service) SubmitPayloadAttestationMessages(ctx context.Context, opts *api.SubmitPayloadAttestationMessagesOpts) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.submitter.immediate").Start(ctx, "SubmitPayloadAttestationMessages")
	defer span.End()

	if opts == nil || len(opts.Messages) == 0 {
		return errors.New("no payload attestation messages supplied")
	}
	if s.payloadAttestationMessagesSubmitter == nil {
		return errors.New("no payload attestation messages submitter specified")
	}
	if err := s.payloadAttestationMessagesSubmitter.SubmitPayloadAttestationMessages(ctx, opts); err != nil {
		return errors.Wrap(err, "failed to submit payload attestation messages")
	}
	return nil
}
