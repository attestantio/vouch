// Copyright © 2021 - 2025 Attestant Limited.
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

package mock

import (
	"context"
	"errors"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// ValidatingAccountsProvider is a mock.
type ValidatingAccountsProvider struct {
	validatingAccounts map[phase0.ValidatorIndex]e2wtypes.Account
}

// NewValidatingAccountsProvider is a mock.
// skipcq: RVV-B0011
func NewValidatingAccountsProvider() *ValidatingAccountsProvider {
	return &ValidatingAccountsProvider{
		validatingAccounts: make(map[phase0.ValidatorIndex]e2wtypes.Account),
	}
}

// HasSlashingProtection returns true if the account manage provides built-in slashing protection.
func (*ValidatingAccountsProvider) HasSlashingProtection() bool {
	return false
}

// AddAccount adds an account to the mock provider.
func (s *ValidatingAccountsProvider) AddAccount(index phase0.ValidatorIndex, account e2wtypes.Account) {
	s.validatingAccounts[index] = account
}

// ValidatingAccountsForEpoch is a mock.
func (s *ValidatingAccountsProvider) ValidatingAccountsForEpoch(_ context.Context, _ phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return s.validatingAccounts, nil
}

// ValidatingAccountsForEpochByIndex obtains the specified validating accounts for a given epoch.
func (s *ValidatingAccountsProvider) ValidatingAccountsForEpochByIndex(_ context.Context,
	_ phase0.Epoch,
	indices []phase0.ValidatorIndex,
) (
	map[phase0.ValidatorIndex]e2wtypes.Account,
	error,
) {
	accounts := make(map[phase0.ValidatorIndex]e2wtypes.Account)
	for _, index := range indices {
		if account, exists := s.validatingAccounts[index]; exists {
			accounts[index] = account
		}
	}

	return accounts, nil
}

// SyncCommitteeAccountsForEpoch is a mock.
func (s *ValidatingAccountsProvider) SyncCommitteeAccountsForEpoch(_ context.Context, _ phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return s.validatingAccounts, nil
}

// SyncCommitteeAccountsForEpochByIndex obtains the specified validating accounts for a given epoch.
func (s *ValidatingAccountsProvider) SyncCommitteeAccountsForEpochByIndex(_ context.Context,
	_ phase0.Epoch,
	indices []phase0.ValidatorIndex,
) (
	map[phase0.ValidatorIndex]e2wtypes.Account,
	error,
) {
	accounts := make(map[phase0.ValidatorIndex]e2wtypes.Account)
	for _, index := range indices {
		if account, exists := s.validatingAccounts[index]; exists {
			accounts[index] = account
		}
	}

	return accounts, nil
}

type accountsProvider struct{}

// NewAccountsProvider is a mock.
func NewAccountsProvider() accountmanager.AccountsProvider {
	return &accountsProvider{}
}

// HasSlashingProtection returns true if the account manage provides built-in slashing protection.
func (*accountsProvider) HasSlashingProtection() bool {
	return false
}

// AccountByPublicKey is a mock.
func (*accountsProvider) AccountByPublicKey(_ context.Context, _ phase0.BLSPubKey) (e2wtypes.Account, error) {
	return nil, nil
}

type refresher struct{}

// NewRefresher is a mock.
func NewRefresher() accountmanager.Refresher {
	return &refresher{}
}

// Refresh is a mock.
func (*refresher) Refresh(_ context.Context) {}

type erroringValidatingAccountsProvider struct{}

// NewErroringValidatingAccountsProvider is a mock.
func NewErroringValidatingAccountsProvider() accountmanager.ValidatingAccountsProvider {
	return &erroringValidatingAccountsProvider{}
}

// HasSlashingProtection returns true if the account manage provides built-in slashing protection.
func (*erroringValidatingAccountsProvider) HasSlashingProtection() bool {
	return false
}

// ValidatingAccountsForEpoch is a mock.
func (*erroringValidatingAccountsProvider) ValidatingAccountsForEpoch(_ context.Context, _ phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return nil, errors.New("error")
}

// ValidatingAccountsForEpochByIndex obtains the specified validating accounts for a given epoch.
func (*erroringValidatingAccountsProvider) ValidatingAccountsForEpochByIndex(_ context.Context,
	_ phase0.Epoch,
	_ []phase0.ValidatorIndex,
) (
	map[phase0.ValidatorIndex]e2wtypes.Account,
	error,
) {
	return nil, errors.New("error")
}

// SyncCommitteeAccountsForEpoch is a mock.
func (*erroringValidatingAccountsProvider) SyncCommitteeAccountsForEpoch(_ context.Context, _ phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return nil, errors.New("error")
}

// SyncCommitteeAccountsForEpochByIndex obtains the specified validating accounts for a given epoch.
func (*erroringValidatingAccountsProvider) SyncCommitteeAccountsForEpochByIndex(_ context.Context,
	_ phase0.Epoch,
	_ []phase0.ValidatorIndex,
) (
	map[phase0.ValidatorIndex]e2wtypes.Account,
	error,
) {
	return nil, errors.New("error")
}
