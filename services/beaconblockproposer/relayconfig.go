// Copyright © 2022 Attestant Limited.
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

package beaconblockproposer

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/shopspring/decimal"
)

var weiPerETH = decimal.New(1e18, 0)

// RelayConfig contains configuration for a relay.
type RelayConfig struct {
	Address      string
	PublicKey    *phase0.BLSPubKey
	FeeRecipient bellatrix.ExecutionAddress
	GasLimit     uint64
	Grace        time.Duration
	MinValue     decimal.Decimal
}

type relayConfigJSON struct {
	Address      string `json:"address"`
	PublicKey    string `json:"public_key,omitempty"`
	FeeRecipient string `json:"fee_recipient"`
	GasLimit     string `json:"gas_limit"`
	Grace        string `json:"grace,omitempty"`
	MinValue     string `json:"min_value,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (r *RelayConfig) MarshalJSON() ([]byte, error) {
	var publicKey string
	if r.PublicKey != nil {
		publicKey = fmt.Sprintf("%#x", *r.PublicKey)
	}
	var grace string
	if r.Grace != 0 {
		grace = fmt.Sprintf("%d", r.Grace.Milliseconds())
	}
	var minValue string
	if !r.MinValue.Equal(decimal.Zero) {
		minValue = fmt.Sprintf("%v", r.MinValue.Div(weiPerETH))
	}
	return json.Marshal(&relayConfigJSON{
		Address:      r.Address,
		PublicKey:    publicKey,
		FeeRecipient: fmt.Sprintf("%#x", r.FeeRecipient),
		GasLimit:     fmt.Sprintf("%d", r.GasLimit),
		Grace:        grace,
		MinValue:     minValue,
	})
}

// String provides a string representation of the struct.
func (r *RelayConfig) String() string {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Sprintf("ERR: %v\n", err)
	}
	return string(data)
}
