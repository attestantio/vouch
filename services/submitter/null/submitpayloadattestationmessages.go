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

package null

import (
	"context"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/pkg/errors"
)

// SubmitPayloadAttestationMessages accepts payload attestation messages without submitting them.
func (*Service) SubmitPayloadAttestationMessages(_ context.Context, opts *api.SubmitPayloadAttestationMessagesOpts) error {
	if opts == nil || len(opts.Messages) == 0 {
		return errors.New("no payload attestation messages supplied")
	}
	return nil
}
