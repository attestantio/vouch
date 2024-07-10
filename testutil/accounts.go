// Copyright © 2020 - 2024 Attestant Limited.
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

package testutil

import (
	"context"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	nd "github.com/wealdtech/go-eth2-wallet-nd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func CreateMessageIndices() map[phase0.ValidatorIndex][]phase0.CommitteeIndex {
	messageIndices := make(map[phase0.ValidatorIndex][]phase0.CommitteeIndex, 10)
	for validatorIndex := range 10 {
		var committeeIndices []phase0.CommitteeIndex
		for syncCommitteeIndex := range 5 {
			committeeIndices = append(committeeIndices, phase0.CommitteeIndex(syncCommitteeIndex))
		}
		messageIndices[phase0.ValidatorIndex(validatorIndex)] = committeeIndices
	}
	return messageIndices
}

func CreateTestWalletAndAccounts(validatorIndices []phase0.ValidatorIndex, hex string) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	accountMapping := make(map[phase0.ValidatorIndex]e2wtypes.Account)
	err := e2types.InitBLS()
	if err != nil {
		return nil, err
	}
	store := scratch.New()
	err = e2wallet.UseStore(store)
	if err != nil {
		return nil, err
	}
	testWallet, err := nd.CreateWallet(context.Background(), "Test wallet", store, keystorev4.New())
	if err != nil {
		return nil, err
	}
	err = testWallet.(e2wtypes.WalletLocker).Unlock(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	for _, validatorIndex := range validatorIndices {
		testAccount, walletErr := testWallet.(e2wtypes.WalletAccountImporter).ImportAccount(context.Background(),
			fmt.Sprintf("Interop %d", validatorIndex),
			HexToBytes(hex),
			[]byte("pass"),
		)
		accountMapping[validatorIndex] = testAccount
		if walletErr != nil {
			return nil, walletErr
		}
	}
	return accountMapping, nil
}
