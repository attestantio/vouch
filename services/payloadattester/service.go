// Copyright © 2026 Attestant Limited.
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

package payloadattester

import (
	"context"

	"github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Duty contains the validator and slot for a payload attestation duty.
type Duty struct {
	slot             phase0.Slot
	validatorIndices []phase0.ValidatorIndex
	accounts         map[phase0.ValidatorIndex]e2wtypes.Account
}

// NewDuty creates a payload attestation duty.
func NewDuty(duty *v1.PTCDuty) *Duty {
	return &Duty{
		slot:             duty.Slot,
		validatorIndices: []phase0.ValidatorIndex{duty.ValidatorIndex},
		accounts:         make(map[phase0.ValidatorIndex]e2wtypes.Account),
	}
}

// AddDuty adds a validator's duty to this slot's duty.
func (d *Duty) AddDuty(duty *v1.PTCDuty) {
	if duty == nil || duty.Slot != d.slot {
		return
	}
	for _, index := range d.validatorIndices {
		if index == duty.ValidatorIndex {
			return
		}
	}
	d.validatorIndices = append(d.validatorIndices, duty.ValidatorIndex)
}

// Slot returns the slot for the duty.
func (d *Duty) Slot() phase0.Slot {
	return d.slot
}

// ValidatorIndex returns the validator index for the duty.
func (d *Duty) ValidatorIndex() phase0.ValidatorIndex {
	if len(d.validatorIndices) == 0 {
		return 0
	}
	return d.validatorIndices[0]
}

// ValidatorIndices returns all validator indices assigned to this slot.
func (d *Duty) ValidatorIndices() []phase0.ValidatorIndex {
	return d.validatorIndices
}

// SetAccount associates an account with a validator index.
func (d *Duty) SetAccount(index phase0.ValidatorIndex, account e2wtypes.Account) {
	d.accounts[index] = account
}

// Account returns the account for a validator index.
func (d *Duty) Account(index phase0.ValidatorIndex) e2wtypes.Account {
	return d.accounts[index]
}

// Accounts returns the accounts associated with the duty.
func (d *Duty) Accounts() map[phase0.ValidatorIndex]e2wtypes.Account {
	return d.accounts
}

// Service is the payload attester service.
type Service interface {
	Prepare(ctx context.Context, duty *Duty) error
	Attest(ctx context.Context, duty *Duty) ([]*spec.VersionedPayloadAttestationMessage, error)
}

var (
	_ signer.PayloadAttestationDataSigner
	_ submitter.PayloadAttestationMessagesSubmitter
)
