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

// Package proposerpreferences provides proposer-preferences duties.
package proposerpreferences

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Duty contains the data required to publish a validator's proposer preferences.
type Duty struct {
	DependentRoot  phase0.Root
	ProposalSlot   phase0.Slot
	ValidatorIndex phase0.ValidatorIndex
	Account        e2wtypes.Account
	FeeRecipient   bellatrix.ExecutionAddress
	TargetGasLimit uint64
}

// NewDuty creates a proposer-preferences duty.
func NewDuty(dependentRoot phase0.Root,
	proposalSlot phase0.Slot,
	validatorIndex phase0.ValidatorIndex,
	account e2wtypes.Account,
	feeRecipient bellatrix.ExecutionAddress,
	targetGasLimit uint64,
) *Duty {
	return &Duty{
		DependentRoot:  dependentRoot,
		ProposalSlot:   proposalSlot,
		ValidatorIndex: validatorIndex,
		Account:        account,
		FeeRecipient:   feeRecipient,
		TargetGasLimit: targetGasLimit,
	}
}

// Service publishes proposer preferences.
type Service interface {
	Publish(ctx context.Context, duty *Duty) error
}
