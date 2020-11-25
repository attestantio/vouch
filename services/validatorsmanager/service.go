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

// Package validatorsmanager is a package that manages validator information,
// primarily from local information and backed by the data from a beacon node.
package validatorsmanager

import (
	"context"

	api "github.com/attestantio/go-eth2-client/api/v1"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
)

// Service is the generic validators manager service.
type Service interface {
	// RefreshValidatorsFromBeaconNode refreshes the local store from the beacon node.
	// This is an expensive operation, and should not be called in the validating path.
	RefreshValidatorsFromBeaconNode(ctx context.Context, pubKeys []spec.BLSPubKey) error

	// ValidatorsByIndex fetches the requested validators from local store given their indices.
	ValidatorsByIndex(ctx context.Context, indices []spec.ValidatorIndex) map[spec.ValidatorIndex]*spec.Validator

	// ValidatorsByPubKey fetches the requested validators from local store given their public keys.
	ValidatorsByPubKey(ctx context.Context, pubKeys []spec.BLSPubKey) map[spec.ValidatorIndex]*spec.Validator

	// ValidatorStateAtEpoch returns the given validator's state at the given epoch.
	ValidatorStateAtEpoch(ctx context.Context, index spec.ValidatorIndex, epoch spec.Epoch) (api.ValidatorState, error)
}
