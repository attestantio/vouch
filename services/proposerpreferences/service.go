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
	CurrentSlot    phase0.Slot
	CurrentEpoch   phase0.Epoch
	ValidatorIndex phase0.ValidatorIndex
	Account        e2wtypes.Account
	FeeRecipient   bellatrix.ExecutionAddress
	TargetGasLimit uint64
}

// SimpleProvider is the readiness name of the simple proposal style's multiclient.  It is ready
// once every proposal provider has accepted the current preference.
const SimpleProvider = "simple"

// ProviderReadiness reports whether a proposal provider has accepted a current preference.
// Callers ask only about builder-backed proposals.
type ProviderReadiness interface {
	ProviderReady(provider string, proposalSlot phase0.Slot, validatorIndex phase0.ValidatorIndex) bool
}

// Publisher publishes proposer preferences.
type Publisher interface {
	UpdateDependentRoot(fromSlot phase0.Slot, toSlot phase0.Slot, root phase0.Root)
	Prune(slot phase0.Slot)
	// Publish publishes the supplied duty's proposer preferences.
	// It returns an error only if no provider has accepted the preferences.
	Publish(ctx context.Context, duty *Duty) error
	FlushConfigChangeWarnings()
}

// Service publishes proposer preferences and reports provider readiness.
type Service interface {
	Publisher
	ProviderReadiness
}
