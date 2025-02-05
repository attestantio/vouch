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
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Duty contains information about an attestation aggregation duty.
type Duty struct {
	// Slot is the slot of the attestation aggregation; required for obtaining the aggregate.
	Slot phase0.Slot
	// Attestation data root is the root of the attestation to be aggregated; required for obtaining the aggregate.
	AttestationDataRoot phase0.Root
	// ValidatorIndex is the index of the validator carrying out the aggregation; required for submitting the aggregate.
	ValidatorIndex phase0.ValidatorIndex
	// SlotSignature is the signature of the slot by the validator carrying out the aggregation; required for submitting the aggregate.
	SlotSignature phase0.BLSSignature
	// CommitteeIndex is the committee index of the validator carrying out the aggregation; required for submitting the aggregate.
	CommitteeIndex phase0.CommitteeIndex
}

// Service is the attestation aggregation service.
type Service interface {
	// Aggregate carries out aggregation for a slot and committee.
	Aggregate(ctx context.Context, details *Duty)

	// AggregatorsAndSignatures reports signatures and whether validators are attestation aggregators for a given slot.
	AggregatorsAndSignatures(ctx context.Context,
		accounts []e2wtypes.Account,
		slot phase0.Slot,
		committeeSizes []uint64,
	) ([]phase0.BLSSignature, []bool, error)
}
