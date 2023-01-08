// Copyright © 2021, 2022 Attestant Limited.
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

type validatingAccountsProvider struct {
	validatingAccounts map[phase0.ValidatorIndex]e2wtypes.Account
}

// NewValidatingAccountsProvider is a mock.
//nolint
// skipcq: RVV-B0011
func NewValidatingAccountsProvider() *validatingAccountsProvider {
	return &validatingAccountsProvider{
		validatingAccounts: make(map[phase0.ValidatorIndex]e2wtypes.Account),
	}
}

// AddAccount adds an account to the mock provider.
func (s *validatingAccountsProvider) AddAccount(index phase0.ValidatorIndex, account e2wtypes.Account) {
	s.validatingAccounts[index] = account
}

// ValidatingAccountsForEpoch is a mock.
func (s *validatingAccountsProvider) ValidatingAccountsForEpoch(_ context.Context, _ phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return s.validatingAccounts, nil
}

// ValidatingAccountsForEpochByIndex obtains the specified validating accounts for a given epoch.
func (s *validatingAccountsProvider) ValidatingAccountsForEpochByIndex(_ context.Context,
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
