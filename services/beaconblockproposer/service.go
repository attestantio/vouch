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

package beaconblockproposer

import (
	"context"
	"fmt"
)

// Duty contains information about a beacon block proposal duty.
type Duty struct {
	// Details for the duty.
	slot           uint64
	validatorIndex uint64

	// randaoReveal is required to be passed to the beacon node when proposing the block; can be pre-calculated.
	randaoReveal []byte
}

// NewDuty creates a new beacon block proposer duty.
func NewDuty(ctx context.Context, slot uint64, validatorIndex uint64) (*Duty, error) {
	return &Duty{
		slot:           slot,
		validatorIndex: validatorIndex,
	}, nil
}

// Slot provides the slot for the beacon block proposer.
func (d *Duty) Slot() uint64 {
	return d.slot
}

// ValidatorIndex provides the validator index for the beacon block proposer.
func (d *Duty) ValidatorIndex() uint64 {
	return d.validatorIndex
}

// String provides a friendly string for the struct.
func (d *Duty) String() string {
	return fmt.Sprintf("beacon block proposal %d@%d", d.validatorIndex, d.slot)
}

// SetRandaoReveal sets the RANDAO reveal.
func (d *Duty) SetRandaoReveal(randaoReveal []byte) {
	d.randaoReveal = randaoReveal
}

// RANDAOReveal provides the RANDAO reveal.
func (d *Duty) RANDAOReveal() []byte {
	return d.randaoReveal
}

// Service is the beacon block proposer service.
type Service interface {
	// Prepare prepares the proposal for a slot.
	Prepare(ctx context.Context, details interface{}) error

	// Propose carries out the proposal for a slot.
	Propose(ctx context.Context, details interface{})
}
