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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
)

type validatingAccount struct {
	index uint64
	key   *bls.SecretKey
}

func (a *validatingAccount) PubKey(ctx context.Context) ([]byte, error) {
	return a.key.GetPublicKey().Serialize(), nil
}

func (a *validatingAccount) Index(ctx context.Context) (uint64, error) {
	return a.index, nil
}

func (a *validatingAccount) State() api.ValidatorState {
	return api.ValidatorStateActiveOngoing
}

func (a *validatingAccount) SignSlotSelection(ctx context.Context, slot uint64, signatureDomain []byte) ([]byte, error) {
	slotBytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(slotBytes, slot)

	hash := sha256.New()
	n, err := hash.Write(slotBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to write slot")
	}
	if n != 32 {
		return nil, errors.New("failed to write all slot bytes")
	}
	n, err = hash.Write(signatureDomain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to write signature domain")
	}
	if n != 32 {
		return nil, errors.New("failed to write all signature domain bytes")
	}

	root := hash.Sum(nil)

	sig := a.key.SignByte(root)
	return sig.Serialize(), nil
}

// ValidatingAccountsProvider is a mock for accountmanager.ValidatingAccountsProvider.
type ValidatingAccountsProvider struct {
	validatingAccounts []accountmanager.ValidatingAccount
}

func _secretKey(input string) *bls.SecretKey {
	bytes, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		panic(err)
	}
	var key bls.SecretKey
	if err := key.Deserialize(bytes); err != nil {
		panic(err)
	}
	return &key
}

// NewValidatingAccountsProvider returns a mock account manager with pre-configured keys.
func NewValidatingAccountsProvider() accountmanager.ValidatingAccountsProvider {
	validatingAccounts := []accountmanager.ValidatingAccount{
		&validatingAccount{
			index: 5184,
			key:   _secretKey("0x01e748d098d3bcb477d636f19d510399ae18205fadf9814ee67052f88c1f77c0"),
		},
		&validatingAccount{
			index: 5221,
			key:   _secretKey("0x376880b8079dca3bbd06c93958b5208929cbc169c9ce4caf8731be10e94f710e"),
		},
		&validatingAccount{
			index: 14499,
			key:   _secretKey("0x3fb0a5e8ec5f9f421b682d8956e08e02af5ed921e7f82a78cc6258869c283500"),
		},
		&validatingAccount{
			index: 14096,
			key:   _secretKey("0x1432f616d724ebe44ba92c603496627dc9a4899ffa7956948caa4a9cebaac171"),
		},
		&validatingAccount{
			index: 14407,
			key:   _secretKey("0x5dc083116a71299cbd8582ab0da28c32f64359039d1f5f5f4a664d2c7deb258e"),
		},
		&validatingAccount{
			index: 13885,
			key:   _secretKey("0x1d6b5e0a9c9c05b7a318602ac1f204c83b6fd2ff8e7b7a3de0aa5e9ff42df071"),
		},
		&validatingAccount{
			index: 13743,
			key:   _secretKey("0x6f91850e101d59b80cc77faa3658c730653827413e653dbdaf9ecfd727cb72e7"),
		},
		&validatingAccount{
			index: 13594,
			key:   _secretKey("0x63510d1383f4ab8285a5b47f6e36da895c2eabd892d580f9820d1c2cf65bc2a9"),
		},
		&validatingAccount{
			index: 13796,
			key:   _secretKey("0x1f9a5ceb86e03e0e94154b4bb7774d8e0cb0dafbe52c8c82acec775723a1e288"),
		},
		&validatingAccount{
			index: 14201,
			key:   _secretKey("0x11d9711e3d67e6b4ea5bf3485babcd365eef48bb9c69b1c89f689e31d5cf5fe2"),
		},
		&validatingAccount{
			index: 13790,
			key:   _secretKey("0x10c0c8b5ca8fdfba14819373e13f4c980f125a075f4c4edce3b32ad037c93740"),
		},
		&validatingAccount{
			index: 13981,
			key:   _secretKey("0x28939bb5986f4074172417273f4174e4cddf75a1f88595cd9d4b6082cbf476fa"),
		},
		&validatingAccount{
			index: 13643,
			key:   _secretKey("0x3662b248e8cfe57e99e73a9e57e7fe0ee9244880b5c9284e8d878c64aca6b5fc"),
		},
		&validatingAccount{
			index: 13536,
			key:   _secretKey("0x281c019804bf23792963095041d1db1f8b79df49d31b07c9cbed1994ff794974"),
		},
		&validatingAccount{
			index: 13673,
			key:   _secretKey("0x15d98ae5d17b78b159dd7feee9aee7b3a7dbaf4777de92da004eb3b46101c5a1"),
		},
		&validatingAccount{
			index: 14032,
			key:   _secretKey("0x6099d69ff55e3dfeba26a4c7db572b7d34792e090704f0eef9ae149260de909f"),
		},
		&validatingAccount{
			index: 14370,
			key:   _secretKey("0x4e693b831328f20818df32fafd50be61daf7cb7de6b96a8767fc183a8e9bfa76"),
		},
		&validatingAccount{
			index: 14368,
			key:   _secretKey("0x0e0c93d7fe17ef80ced6f431dd482abd02530f29294b2f47318da24d82fb54ef"),
		},
	}

	return &ValidatingAccountsProvider{
		validatingAccounts: validatingAccounts,
	}
}

// Accounts returns accounts.
func (m *ValidatingAccountsProvider) Accounts(ctx context.Context) ([]accountmanager.ValidatingAccount, error) {
	return m.validatingAccounts, nil
}

// AccountsByIndex returns accounts.
func (m *ValidatingAccountsProvider) AccountsByIndex(ctx context.Context, indices []uint64) ([]accountmanager.ValidatingAccount, error) {
	indexMap := make(map[uint64]bool)
	for _, index := range indices {
		indexMap[index] = true
	}

	res := make([]accountmanager.ValidatingAccount, 0)
	for _, validatingAccount := range m.validatingAccounts {
		index, err := validatingAccount.Index(ctx)
		if err != nil {
			continue
		}
		if _, required := indexMap[index]; required {
			res = append(res, validatingAccount)
		}
	}
	return res, nil
}

// AccountsByPubKey returns accounts.
func (m *ValidatingAccountsProvider) AccountsByPubKey(ctx context.Context, pubKeys [][]byte) ([]accountmanager.ValidatingAccount, error) {
	keyMap := make(map[string]bool)
	for _, pubKey := range pubKeys {
		keyMap[fmt.Sprintf("%x", pubKey)] = true
	}

	res := make([]accountmanager.ValidatingAccount, 0)
	for _, validatingAccount := range m.validatingAccounts {
		publicKey, err := validatingAccount.PubKey(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain public key of account")
		}
		pubKey := fmt.Sprintf("%x", publicKey)
		if _, required := keyMap[pubKey]; required {
			res = append(res, validatingAccount)
		}
	}
	return res, nil
}
