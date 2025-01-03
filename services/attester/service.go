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

package attester

import (
	"context"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// Duty contains information about beacon block attester duties for a given slot.
type Duty struct {
	slot                      phase0.Slot
	committeesAtSlot          uint64
	validatorIndices          []phase0.ValidatorIndex
	committeeIndices          []phase0.CommitteeIndex
	validatorCommitteeIndices []uint64
	committeeLengths          map[phase0.CommitteeIndex]uint64
}

// NewDuty creates a new beacon block attester duty.
func NewDuty(_ context.Context,
	slot phase0.Slot,
	committeesAtSlot uint64,
	validatorIndices []phase0.ValidatorIndex,
	committeeIndices []phase0.CommitteeIndex,
	validatorCommitteeIndices []uint64,
	committeeLengths map[phase0.CommitteeIndex]uint64,
) (*Duty, error) {
	// Ensure there is a matching committee size for each committee index.
	for i := range committeeIndices {
		if _, exists := committeeLengths[committeeIndices[i]]; !exists {
			return nil, fmt.Errorf("committee %d does not have a committee size; duty invalid", committeeIndices[i])
		}
	}

	return &Duty{
		slot:                      slot,
		committeesAtSlot:          committeesAtSlot,
		validatorIndices:          validatorIndices,
		committeeIndices:          committeeIndices,
		validatorCommitteeIndices: validatorCommitteeIndices,
		committeeLengths:          committeeLengths,
	}, nil
}

// Slot provides the slot for the beacon block attester.
func (d *Duty) Slot() phase0.Slot {
	return d.slot
}

// CommitteesAtSlot provides the number of committees at the duty's slot.
func (d *Duty) CommitteesAtSlot() uint64 {
	return d.committeesAtSlot
}

// ValidatorIndices provides the validator indices for the beacon block attester.
func (d *Duty) ValidatorIndices() []phase0.ValidatorIndex {
	return d.validatorIndices
}

// CommitteeIndices provides the committee indices for the beacon block attester.
func (d *Duty) CommitteeIndices() []phase0.CommitteeIndex {
	return d.committeeIndices
}

// ValidatorCommitteeIndices provides the indices of validators within committees for the beacon block attester.
func (d *Duty) ValidatorCommitteeIndices() []uint64 {
	return d.validatorCommitteeIndices
}

// CommitteeSize provides the committee size for a given index.
func (d *Duty) CommitteeSize(committeeIndex phase0.CommitteeIndex) uint64 {
	return d.committeeLengths[committeeIndex]
}

// String provides a friendly string for the struct's main details.
func (d *Duty) String() string {
	return fmt.Sprintf("beacon block attester for slot %d with validators %v committee indices %v", d.slot, d.validatorIndices, d.committeeIndices)
}

// Tuples returns a slice of (validator index, committee index, validator position in committee) strings.
func (d *Duty) Tuples() []string {
	tuples := make([]string, len(d.committeeIndices))
	for i := range d.committeeIndices {
		tuples[i] = fmt.Sprintf("(%d,%d,%d)",
			d.validatorIndices[i],
			d.committeeIndices[i],
			d.validatorCommitteeIndices[i],
		)
	}
	return tuples
}

// Service is the beacon block attester service.
type Service interface {
	// Attest carries out attestations for a slot.
	// It returns a list of attestations made.
	Attest(ctx context.Context, duty *Duty) ([]*phase0.Attestation, error)

	// AttestVersioned carries out the attestations for a slot.
	// It returns a list of versioned attestations made.
	AttestVersioned(ctx context.Context, duty *Duty) ([]*spec.VersionedAttestation, error)
}
