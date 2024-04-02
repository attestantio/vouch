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

package util

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// ValidatorPubkey returns the public key of the validator associated with the account.
func ValidatorPubkey(account e2wtypes.Account) phase0.BLSPubKey {
	var pubkey phase0.BLSPubKey
	if provider, isProvider := account.(e2wtypes.AccountCompositePublicKeyProvider); isProvider {
		copy(pubkey[:], provider.CompositePublicKey().Marshal())
	} else {
		copy(pubkey[:], account.PublicKey().Marshal())
	}

	return pubkey
}
