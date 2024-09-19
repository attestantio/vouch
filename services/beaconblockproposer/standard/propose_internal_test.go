// Copyright © 2024 Attestant Limited.
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

package standard

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func duty(slot phase0.Slot, validatorIndex phase0.ValidatorIndex, randaoReveal phase0.BLSSignature, account e2wtypes.Account) *beaconblockproposer.Duty {
	duty := beaconblockproposer.NewDuty(slot, validatorIndex)
	duty.SetRandaoReveal(randaoReveal)
	duty.SetAccount(account)
	return duty
}

func TestValidateDuty(t *testing.T) {
	ctx := context.Background()

	// Create an account.
	require.NoError(t, e2types.InitBLS())
	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := hd.CreateWallet(ctx, "test wallet", []byte("pass"), store, encryptor, make([]byte, 64))
	require.NoError(t, err)
	require.Nil(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, []byte("pass")))
	account, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(context.Background(), "test account", []byte("pass"))
	require.NoError(t, err)
	require.NoError(t, account.(e2wtypes.AccountLocker).Unlock(ctx, []byte("pass")))

	sig, err := account.(e2wtypes.AccountSigner).Sign(ctx, []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	})
	require.NoError(t, err)
	randaoReveal := phase0.BLSSignature(sig.Marshal())

	tests := []struct {
		name string
		duty *beaconblockproposer.Duty
		slot phase0.Slot
		err  string
	}{
		{
			name: "Nil",
			err:  "no duty supplied",
		},
		{
			name: "NoRandaoReveal",
			duty: duty(1, 2, phase0.BLSSignature{}, account),
			err:  "duty missing RANDAO reveal",
		},
		{
			name: "NoAccount",
			duty: duty(1, 2, randaoReveal, nil),
			err:  "duty missing account",
		},
		{
			name: "Good",
			duty: duty(1, 2, randaoReveal, account),
			slot: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			slot, err := validateDuty(test.duty)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.slot, slot)
			}
		})
	}
}
