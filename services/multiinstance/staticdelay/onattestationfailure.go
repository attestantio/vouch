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

package staticdelay

import (
	"context"

	"github.com/attestantio/vouch/services/attester"
)

// OnAttestationFailure flags that an attempt to attest has failed.
func (s *Service) OnAttestationFailure(ctx context.Context, duty *attester.Duty) {
	s.log.Trace().Uint64("slot", uint64(duty.Slot())).Msg("Attestation failure; deactivating")

	s.disableAttester(ctx)
}
