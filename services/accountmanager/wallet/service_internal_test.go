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

package wallet

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/validatorsmanager"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/attestantio/vouch/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func setupServiceWithValidatorsManager(ctx context.Context, t *testing.T, validatorsManager validatorsmanager.Service) (*Service, error) {
	chainTime, specProvider := testutil.NewTestChainTime(ctx, t)

	return New(ctx,
		WithLogLevel(zerolog.TraceLevel),
		WithMonitor(nullmetrics.New()),
		WithProcessConcurrency(1),
		WithAccountPaths([]string{"wallet1"}),
		WithPassphrases([][]byte{[]byte("pass")}),
		WithValidatorsManager(validatorsManager),
		WithSpecProvider(specProvider),
		WithDomainProvider(mock.NewDomainProvider()),
		WithFarFutureEpochProvider(mock.NewFarFutureEpochProvider(0xffffffffffffffff)),
		WithCurrentEpochProvider(chainTime),
	)
}

func TestAccountsForEpochWithFilterLogging(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, e2types.InitBLS())

	// Create wallet with known seed.
	store := scratch.New()
	encryptor := keystorev4.New()
	seed := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	}
	wallet, err := hd.CreateWallet(ctx, "test-wallet", []byte("pass"), store, encryptor, seed)
	require.NoError(t, err)
	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, []byte("pass")))
	account, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(ctx, "account1", []byte("pass"))
	require.NoError(t, err)

	// Convert account public key to phase0.BLSPubKey.
	var pubKey phase0.BLSPubKey
	copy(pubKey[:], account.PublicKey().Marshal())

	// Create configurable validators manager with an ActiveOngoing validator.
	validatorsManager := mock.NewConfigurableValidatorsManager()
	validatorsManager.AddValidator(phase0.ValidatorIndex(456), &phase0.Validator{
		PublicKey:                  pubKey,
		WithdrawalCredentials:      make([]byte, 32),
		EffectiveBalance:           32000000000, // 32 ETH
		Slashed:                    false,
		ActivationEligibilityEpoch: 0,
		ActivationEpoch:            0,                  // Active from epoch 0.
		ExitEpoch:                  0xffffffffffffffff, // Far future - active ongoing.
		WithdrawableEpoch:          0xffffffffffffffff,
	})

	// Create service with log capture.
	capture := logger.NewLogCapture()
	s, err := setupServiceWithValidatorsManager(ctx, t, validatorsManager)
	require.NoError(t, err)

	// Manually populate accounts map.
	s.accounts = map[phase0.BLSPubKey]e2wtypes.Account{
		pubKey: account,
	}

	// Call ValidatingAccountsForEpoch to trigger the logging.
	accounts, err := s.ValidatingAccountsForEpoch(ctx, phase0.Epoch(1))
	require.NoError(t, err)
	require.Len(t, accounts, 1)

	// Find the log entry and validate the public_key field.
	var foundEntry map[string]any
	for _, entry := range capture.Entries() {
		if msg, ok := entry["message"].(string); ok && msg == "Validating account" {
			foundEntry = entry
			break
		}
	}
	require.NotNil(t, foundEntry, "Expected 'Validating account' log entry")

	// Validate the public_key field.
	pubKeyValue, ok := foundEntry["public_key"].(string)
	require.True(t, ok, "public_key field should be a string")

	// Validate it matches the expected value.
	require.Equal(t, pubKey.String(), pubKeyValue)

	// Validate it's a valid Ethereum BLS public key format.
	testutil.AssertValidBLSPubKeyFormat(t, pubKeyValue)
}
