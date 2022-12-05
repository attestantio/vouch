// Copyright © 2020 Attestant Limited.
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

package standard

import (
	"context"

	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
)

// ValidatorStateAtEpoch returns the validator's state at the given epoch.
func (s *Service) ValidatorStateAtEpoch(ctx context.Context, index phase0.ValidatorIndex, epoch phase0.Epoch) (api.ValidatorState, error) {
	_, span := otel.Tracer("attestantio.vouch.services.validatorsmanager.standard").Start(ctx, "ValidatorStateAtEpoch")
	defer span.End()

	s.validatorsMutex.RLock()
	validator, exists := s.validatorsByIndex[index]
	s.validatorsMutex.RUnlock()
	if !exists {
		return api.ValidatorStateUnknown, errors.New("not found")
	}
	return api.ValidatorToState(validator, epoch, s.farFutureEpoch), nil
}
