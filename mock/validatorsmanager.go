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
func (*validatorsManager) RefreshValidatorsFromBeaconNode(_ context.Context, _ []phase0.BLSPubKey) error {
	return nil
}

// ValidatorsByIndex is a mock.
func (*validatorsManager) ValidatorsByIndex(_ context.Context, _ []phase0.ValidatorIndex) map[phase0.ValidatorIndex]*phase0.Validator {
	return make(map[phase0.ValidatorIndex]*phase0.Validator)
}

// ValidatorsByIndex is a mock.
func (*validatorsManager) ValidatorsByPubKey(_ context.Context, _ []phase0.BLSPubKey) map[phase0.ValidatorIndex]*phase0.Validator {
	return make(map[phase0.ValidatorIndex]*phase0.Validator)
}

// ValidatorStateAtEpoch is a mock.
func (*validatorsManager) ValidatorStateAtEpoch(_ context.Context, _ phase0.ValidatorIndex, _ phase0.Epoch) (api.ValidatorState, error) {
	return api.ValidatorStateUnknown, nil
}

// ConfigurableValidatorsManager is a mock validators manager with configurable validators.
type ConfigurableValidatorsManager struct {
	validatorsByIndex  map[phase0.ValidatorIndex]*phase0.Validator
	validatorsByPubKey map[phase0.BLSPubKey]phase0.ValidatorIndex
}

// NewConfigurableValidatorsManager creates a configurable validators manager.
func NewConfigurableValidatorsManager() *ConfigurableValidatorsManager {
	return &ConfigurableValidatorsManager{
		validatorsByIndex:  make(map[phase0.ValidatorIndex]*phase0.Validator),
		validatorsByPubKey: make(map[phase0.BLSPubKey]phase0.ValidatorIndex),
	}
}

// AddValidator adds a validator to the mock.
func (m *ConfigurableValidatorsManager) AddValidator(index phase0.ValidatorIndex, validator *phase0.Validator) {
	m.validatorsByIndex[index] = validator
	m.validatorsByPubKey[validator.PublicKey] = index
}

// RefreshValidatorsFromBeaconNode is a mock.
func (*ConfigurableValidatorsManager) RefreshValidatorsFromBeaconNode(_ context.Context, _ []phase0.BLSPubKey) error {
	return nil
}

// ValidatorsByIndex returns validators matching the given indices.
func (m *ConfigurableValidatorsManager) ValidatorsByIndex(_ context.Context, indices []phase0.ValidatorIndex) map[phase0.ValidatorIndex]*phase0.Validator {
	result := make(map[phase0.ValidatorIndex]*phase0.Validator)
	for _, index := range indices {
		if validator, ok := m.validatorsByIndex[index]; ok {
			result[index] = validator
		}
	}
	return result
}

// ValidatorsByPubKey returns validators matching the given public keys.
func (m *ConfigurableValidatorsManager) ValidatorsByPubKey(_ context.Context, pubKeys []phase0.BLSPubKey) map[phase0.ValidatorIndex]*phase0.Validator {
	result := make(map[phase0.ValidatorIndex]*phase0.Validator)
	for _, pk := range pubKeys {
		if idx, ok := m.validatorsByPubKey[pk]; ok {
			result[idx] = m.validatorsByIndex[idx]
		}
	}
	return result
}

// ValidatorStateAtEpoch is a mock.
func (*ConfigurableValidatorsManager) ValidatorStateAtEpoch(_ context.Context, _ phase0.ValidatorIndex, _ phase0.Epoch) (api.ValidatorState, error) {
	return api.ValidatorStateUnknown, nil
}
