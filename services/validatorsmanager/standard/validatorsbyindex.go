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

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
)

// ValidatorsByIndex fetches the requested validators from local store given their indices.
func (s *Service) ValidatorsByIndex(ctx context.Context, indices []spec.ValidatorIndex) map[spec.ValidatorIndex]*spec.Validator {
	res := make(map[spec.ValidatorIndex]*spec.Validator)
	s.validatorsMutex.RLock()
	for _, index := range indices {
		if validator, exists := s.validatorsByIndex[index]; exists {
			res[index] = validator
		}
	}
	s.validatorsMutex.RUnlock()

	return res
}
