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

package mock

import (
	"context"

	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/validatorsmanager"
)

type validatorsManager struct{}

// NewValidatorsManager creates a mock validators manager.
func NewValidatorsManager() validatorsmanager.Service {
	return &validatorsManager{}
}

// RefreshValidatorsFromBeaconNode is a mock.
func (v *validatorsManager) RefreshValidatorsFromBeaconNode(ctx context.Context, pubKeys []phase0.BLSPubKey) error {
	return nil
}

// ValidatorsByIndex is a mock.
func (v *validatorsManager) ValidatorsByIndex(ctx context.Context, indices []phase0.ValidatorIndex) map[phase0.ValidatorIndex]*phase0.Validator {
	return make(map[phase0.ValidatorIndex]*phase0.Validator)
}

// ValidatorsByIndex is a mock.
func (v *validatorsManager) ValidatorsByPubKey(ctx context.Context, pubKeys []phase0.BLSPubKey) map[phase0.ValidatorIndex]*phase0.Validator {
	return make(map[phase0.ValidatorIndex]*phase0.Validator)
}

// ValidatorStateAtEpoch is a mock.
func (v *validatorsManager) ValidatorStateAtEpoch(ctx context.Context, index phase0.ValidatorIndex, epoch phase0.Epoch) (api.ValidatorState, error) {
	return api.ValidatorStateUnknown, nil
}
