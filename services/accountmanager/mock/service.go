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

package mock

import (
	"context"

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type validatingAccountsProvider struct{}

// NewValidatingAccountsProvider is a mock.
func NewValidatingAccountsProvider() accountmanager.ValidatingAccountsProvider {
	return &validatingAccountsProvider{}
}

// ValidatingAccountsForEpoch is a mock.
func (v *validatingAccountsProvider) ValidatingAccountsForEpoch(ctx context.Context, epoch spec.Epoch) (map[spec.ValidatorIndex]e2wtypes.Account, error) {
	return make(map[spec.ValidatorIndex]e2wtypes.Account), nil
}

// ValidatingAccountsForEpochByIndex obtains the specified validating accounts for a given epoch.
func (v *validatingAccountsProvider) ValidatingAccountsForEpochByIndex(ctx context.Context,
	epoch spec.Epoch,
	indices []spec.ValidatorIndex,
) (
	map[spec.ValidatorIndex]e2wtypes.Account,
	error,
) {
	return make(map[spec.ValidatorIndex]e2wtypes.Account), nil
}

type refresher struct{}

// NewRefresher is a mock.
func NewRefresher() accountmanager.Refresher {
	return &refresher{}
}

// Refresh is a mock.
func (r *refresher) Refresh(ctx context.Context) {}
