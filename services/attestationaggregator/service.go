// Copyright © 2020, 2021 Attestant Limited.
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

package attestationaggregator

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// Duty contains information about an attestation aggregation duty.
type Duty struct {
	// Slot is the slot of the attestation aggregation; required for obtaining the aggregate.
	Slot phase0.Slot
	// Attestation data root is the root of the attestation to be aggregated; required for obtaining the aggregate.
	AttestationDataRoot phase0.Root
	// ValidatorIndex is the index of the validator carrying out the aggregation; reuqired for submitting the aggregate.
	ValidatorIndex phase0.ValidatorIndex
	// SlotSignature is the signature of the slot by the validator carrying out the aggregation; reuqired for submitting the aggregate.
	SlotSignature phase0.BLSSignature
}

// IsAggregatorProvider provides information about if a validator is an aggregator.
type IsAggregatorProvider interface {
	// IsAggregator returns true if the given validator is an aggregator for the given committee at the given slot.
	IsAggregator(ctx context.Context, validatorIndex phase0.ValidatorIndex, slot phase0.Slot, committeeSize uint64) (bool, phase0.BLSSignature, error)
}

// Service is the attestation aggregation service.
type Service interface {
	// Aggregate carries out aggregation for a slot and committee.
	Aggregate(ctx context.Context, details interface{})
}
