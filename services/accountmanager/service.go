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

// Package accountmanager is a package that manages validator accounts from multiple sources.
package accountmanager

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is the generic accountmanager service.
type Service interface{}

// ValidatingAccountsProvider provides methods for validating accounts.
type ValidatingAccountsProvider interface {
	// ValidatingAccountsForEpoch obtains the validating accounts for a given epoch.
	ValidatingAccountsForEpoch(ctx context.Context, epoch phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error)

	// ValidatingAccountsForEpochByIndex obtains the specified validating accounts for a given epoch.
	ValidatingAccountsForEpochByIndex(ctx context.Context,
		epoch phase0.Epoch,
		indices []phase0.ValidatorIndex,
	) (
		map[phase0.ValidatorIndex]e2wtypes.Account,
		error,
	)

	// SyncCommitteeAccountsForEpoch obtains the accounts eligible for Sync Committee duty for a given epoch.
	// The Ethereum specification has different criteria for Sync Committee eligibility compared to other validating duties.
	// This includes an edge case where we are still in scope for sync committee duty between exited and withdrawal states.
	SyncCommitteeAccountsForEpoch(ctx context.Context, epoch phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error)

	// SyncCommitteeAccountsForEpochByIndex obtains the specified Sync Committee eligible accounts for a given epoch.
	// The Ethereum specification has different criteria for Sync Committee eligibility compared to other validating duties.
	// This includes an edge case where we are still in scope for sync committee duty between exited and withdrawal states.
	SyncCommitteeAccountsForEpochByIndex(ctx context.Context,
		epoch phase0.Epoch,
		indices []phase0.ValidatorIndex,
	) (
		map[phase0.ValidatorIndex]e2wtypes.Account,
		error,
	)
}

// Refresher refreshes account information from the remote source.
type Refresher interface {
	// Refresh refreshes the accounts from the remote source, and account validator state from
	// the validators provider.
	// This is a relatively expensive operation, so should not be run in the validating path.
	Refresh(ctx context.Context)
}

// AccountsProvider provides accounts.
type AccountsProvider interface {
	// AccountByPublicKey returns the account for the given public key.
	AccountByPublicKey(ctx context.Context, pubkey phase0.BLSPubKey) (e2wtypes.Account, error)
}
