// Copyright © 2021 Attestant Limited.
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

package synccommitteemessenger

import (
	"context"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Duty contains information about a sync committee contribution duty.
type Duty struct {
	// Details for the duty.
	slot                phase0.Slot
	validatorIndices    []phase0.ValidatorIndex
	contributionIndices map[phase0.ValidatorIndex][]phase0.CommitteeIndex

	// account is used to sign the sync committee contribution; can be pre-fetched.
	accounts map[phase0.ValidatorIndex]e2wtypes.Account

	// aggregatorSubcommittees are the subcommittees for which the validator must aggregate.
	aggregatorSubcommittees map[phase0.ValidatorIndex]map[uint64]phase0.BLSSignature
}

// NewDuty creates a new sync committee contribution duty.
func NewDuty(slot phase0.Slot, contributionIndices map[phase0.ValidatorIndex][]phase0.CommitteeIndex) *Duty {
	validatorIndices := make([]phase0.ValidatorIndex, 0, len(contributionIndices))
	for k := range contributionIndices {
		validatorIndices = append(validatorIndices, k)
	}

	return &Duty{
		slot:                    slot,
		validatorIndices:        validatorIndices,
		contributionIndices:     contributionIndices,
		accounts:                make(map[phase0.ValidatorIndex]e2wtypes.Account, len(contributionIndices)),
		aggregatorSubcommittees: make(map[phase0.ValidatorIndex]map[uint64]phase0.BLSSignature),
	}
}

// Slot provides the slot for the sync committee messenger.
func (d *Duty) Slot() phase0.Slot {
	return d.slot
}

// ValidatorIndices provides the validator indices for the sync committee messenger.
func (d *Duty) ValidatorIndices() []phase0.ValidatorIndex {
	return d.validatorIndices
}

// ContributionIndices provides the contribution indices for the sync committee messenger.
func (d *Duty) ContributionIndices() map[phase0.ValidatorIndex][]phase0.CommitteeIndex {
	return d.contributionIndices
}

// String provides a friendly string for the struct.
func (d *Duty) String() string {
	return fmt.Sprintf("sync committee contributions %v", d.Tuples())
}

// Tuples returns a slice of (validator index, committee indices) strings.
func (d *Duty) Tuples() []string {
	res := make([]string, 0, len(d.contributionIndices))
	for k, v := range d.contributionIndices {
		res = append(res, fmt.Sprintf("(%d,%v)", k, v))
	}
	return res
}

// // SetRandaoReveal sets the RANDAO reveal.
// func (d *Duty) SetRandaoReveal(randaoReveal spec.BLSSignature) {
// 	d.randaoReveal = randaoReveal
// }
//
// // RANDAOReveal provides the RANDAO reveal.
// func (d *Duty) RANDAOReveal() spec.BLSSignature {
// 	return d.randaoReveal
// }.

// SetAccount sets the account.
func (d *Duty) SetAccount(index phase0.ValidatorIndex, account e2wtypes.Account) {
	d.accounts[index] = account
}

// Accounts provides all accounts.
func (d *Duty) Accounts() map[phase0.ValidatorIndex]e2wtypes.Account {
	return d.accounts
}

// Account provides a specific account.
func (d *Duty) Account(index phase0.ValidatorIndex) e2wtypes.Account {
	return d.accounts[index]
}

// SetAggregatorSubcommittees sets the aggregator state for a validator.
func (d *Duty) SetAggregatorSubcommittees(index phase0.ValidatorIndex, subcommittee uint64, selectionProof phase0.BLSSignature) {
	_, exists := d.aggregatorSubcommittees[index]
	if !exists {
		d.aggregatorSubcommittees[index] = make(map[uint64]phase0.BLSSignature)
	}
	d.aggregatorSubcommittees[index][subcommittee] = selectionProof
}

// AggregatorSubcommittees returns the map of subcommittees for which the supplied index is an aggregator.
func (d *Duty) AggregatorSubcommittees(index phase0.ValidatorIndex) map[uint64]phase0.BLSSignature {
	aggregatorSubcommittees, exists := d.aggregatorSubcommittees[index]
	if !exists {
		return make(map[uint64]phase0.BLSSignature)
	}
	return aggregatorSubcommittees
}

// Service is the sync committee messenger service.
type Service interface {
	// Prepare prepares in advance of a sync committee message.
	Prepare(ctx context.Context, duty *Duty) error

	// Message generates and broadcasts sync committee messages for a slot.
	// It returns a list of messages made.
	Message(ctx context.Context, duty *Duty) ([]*altair.SyncCommitteeMessage, error)

	// GetDataUsedForSlot returns slot data recorded for the sync committee message for a given slot.
	GetDataUsedForSlot(slot phase0.Slot) (SlotData, bool)

	// RemoveHistoricDataUsedForSlotVerification goes through the sync committee data stored for each slot and removes old slots.
	RemoveHistoricDataUsedForSlotVerification(currentSlot phase0.Slot)
}

// SlotData contains sync committee data for a specific slot.
type SlotData struct {
	Root                      phase0.Root
	ValidatorToCommitteeIndex map[phase0.ValidatorIndex][]phase0.CommitteeIndex
}
