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

	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Duty contains information about a beacon block proposal duty.
type Duty struct {
	// Details for the duty.
	slot           phase0.Slot
	validatorIndex phase0.ValidatorIndex

	// randaoReveal is required to be passed to the beacon node when proposing the block; can be pre-calculated.
	randaoReveal phase0.BLSSignature

	// account is used to sign the proposal; can be pre-fetched.
	account e2wtypes.Account
}

// NewDuty creates a new beacon block proposer duty.
func NewDuty(slot phase0.Slot, validatorIndex phase0.ValidatorIndex) *Duty {
	return &Duty{
		slot:           slot,
		validatorIndex: validatorIndex,
	}
}

// Slot provides the slot for the beacon block proposer.
func (d *Duty) Slot() phase0.Slot {
	return d.slot
}

// ValidatorIndex provides the validator index for the beacon block proposer.
func (d *Duty) ValidatorIndex() phase0.ValidatorIndex {
	return d.validatorIndex
}

// String provides a friendly string for the struct.
func (d *Duty) String() string {
	return fmt.Sprintf("beacon block proposal %d@%d", d.validatorIndex, d.slot)
}

// SetRandaoReveal sets the RANDAO reveal.
func (d *Duty) SetRandaoReveal(randaoReveal phase0.BLSSignature) {
	d.randaoReveal = randaoReveal
}

// RANDAOReveal provides the RANDAO reveal.
func (d *Duty) RANDAOReveal() phase0.BLSSignature {
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
