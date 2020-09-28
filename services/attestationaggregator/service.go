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

package attestationaggregator

import (
	"context"

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
)

// Duty contains information about an attestation aggregation duty.
type Duty struct {
	validatorIndex  uint64
	validatorPubKey []byte
	slotSignature   []byte
	attestation     *spec.Attestation
}

// NewDuty creates a new attestation aggregation duty.
func NewDuty(ctx context.Context, validatorIndex uint64, validatorPubKey []byte, attestation *spec.Attestation, slotSignature []byte) (*Duty, error) {
	return &Duty{
		validatorIndex:  validatorIndex,
		validatorPubKey: validatorPubKey,
		slotSignature:   slotSignature,
		attestation:     attestation,
	}, nil
}

// Slot provides the slot for the attestaton aggregation.
func (d *Duty) Slot() uint64 {
	return d.attestation.Data.Slot
}

// CommitteeIndex provides the committee index for the attestaton aggregation.
func (d *Duty) CommitteeIndex() uint64 {
	return d.attestation.Data.Index
}

// ValidatorIndex provides the index of the validator carrying out the attestation aggregation.
func (d *Duty) ValidatorIndex() uint64 {
	return d.validatorIndex
}

// ValidatorPubKey provides the public key of the validator carrying out the attestation aggregation.
func (d *Duty) ValidatorPubKey() []byte {
	return d.validatorPubKey
}

// Attestation provides the attestation of the validator carrying out the attestation aggregation.
func (d *Duty) Attestation() *spec.Attestation {
	return d.attestation
}

// SlotSignature provides the slot signature of the validator carrying out the attestation aggregation.
func (d *Duty) SlotSignature() []byte {
	return d.slotSignature
}

// IsAggregatorProvider provides information about if a validator is an aggregator.
type IsAggregatorProvider interface {
	// IsAggregator returns true if the given validator is an aggregator for the given committee at the given slot.
	IsAggregator(ctx context.Context, validatorIndex uint64, committeeIndex uint64, slot uint64, committeeSize uint64) (bool, []byte, error)
}

// Service is the attestation aggregation service.
type Service interface {
	// Aggregate carries out aggregation for a slot and committee.
	Aggregate(ctx context.Context, details interface{})
}
