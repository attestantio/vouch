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

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Duty contains information about a beacon block proposal duty.
type Duty struct {
	// Details for the duty.
	slot           spec.Slot
	validatorIndex spec.ValidatorIndex

	// randaoReveal is required to be passed to the beacon node when proposing the block; can be pre-calculated.
	randaoReveal spec.BLSSignature

	// account is used to sign the proposal; can be pre-fetched.
	account e2wtypes.Account
}

// NewDuty creates a new beacon block proposer duty.
func NewDuty(slot spec.Slot, validatorIndex spec.ValidatorIndex) *Duty {
	return &Duty{
		slot:           slot,
		validatorIndex: validatorIndex,
	}
}

// Slot provides the slot for the beacon block proposer.
func (d *Duty) Slot() spec.Slot {
	return d.slot
}

// ValidatorIndex provides the validator index for the beacon block proposer.
func (d *Duty) ValidatorIndex() spec.ValidatorIndex {
	return d.validatorIndex
}

// String provides a friendly string for the struct.
func (d *Duty) String() string {
	return fmt.Sprintf("beacon block proposal %d@%d", d.validatorIndex, d.slot)
}

// SetRandaoReveal sets the RANDAO reveal.
func (d *Duty) SetRandaoReveal(randaoReveal spec.BLSSignature) {
	d.randaoReveal = randaoReveal
}

// RANDAOReveal provides the RANDAO reveal.
func (d *Duty) RANDAOReveal() spec.BLSSignature {
	return d.randaoReveal
}

// SetAccount sets the account.
func (d *Duty) SetAccount(account e2wtypes.Account) {
	d.account = account
}

// Account provides the account.
func (d *Duty) Account() e2wtypes.Account {
	return d.account
}

// Service is the beacon block proposer service.
type Service interface {
	// Prepare prepares the proposal for a slot.
	Prepare(ctx context.Context, details interface{}) error

	// Propose carries out the proposal for a slot.
	Propose(ctx context.Context, details interface{})
}
