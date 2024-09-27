// Copyright © 2022 Atestant Limited.
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

package v2

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
)

// ProposerRelayConfig handles config information for the proposer relay.
type ProposerRelayConfig struct {
	Disabled     bool
	PublicKey    *phase0.BLSPubKey
	FeeRecipient *bellatrix.ExecutionAddress
	GasLimit     *uint64
	Grace        *time.Duration
	MinValue     *decimal.Decimal
}

type proposerRelayConfigJSON struct {
	Disabled     bool   `json:"disabled,omitempty"`
	PublicKey    string `json:"public_key,omitempty"`
	FeeRecipient string `json:"fee_recipient,omitempty"`
	GasLimit     string `json:"gas_limit,omitempty"`
	Grace        string `json:"grace,omitempty"`
	MinValue     string `json:"min_value,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (c *ProposerRelayConfig) MarshalJSON() ([]byte, error) {
	var publicKey string
	if c.PublicKey != nil {
		publicKey = fmt.Sprintf("%#x", *c.PublicKey)
	}
	var feeRecipient string
	if c.FeeRecipient != nil {
		feeRecipient = fmt.Sprintf("%#x", *c.FeeRecipient)
	}
	var gasLimit string
	if c.GasLimit != nil {
		gasLimit = fmt.Sprintf("%d", *c.GasLimit)
	}
	var grace string
	if c.Grace != nil {
		grace = fmt.Sprintf("%d", c.Grace.Milliseconds())
	}
	var minValue string
	if c.MinValue != nil {
		minValue = fmt.Sprintf("%v", c.MinValue.Div(weiPerETH))
	}
	return json.Marshal(&proposerRelayConfigJSON{
		Disabled:     c.Disabled,
		PublicKey:    publicKey,
		FeeRecipient: feeRecipient,
		GasLimit:     gasLimit,
		Grace:        grace,
		MinValue:     minValue,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (c *ProposerRelayConfig) UnmarshalJSON(input []byte) error {
	var data proposerRelayConfigJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	c.Disabled = data.Disabled
	if data.PublicKey != "" {
		tmp, err := hex.DecodeString(strings.TrimPrefix(data.PublicKey, "0x"))
		if err != nil {
			return errors.Wrap(err, "failed to decode public key")
		}
		if len(tmp) != phase0.PublicKeyLength {
			return errors.New("incorrect length for public key")
		}
		var publicKey phase0.BLSPubKey
		copy(publicKey[:], tmp)
		c.PublicKey = &publicKey
	}
	if data.FeeRecipient != "" {
		tmp, err := hex.DecodeString(strings.TrimPrefix(data.FeeRecipient, "0x"))
		if err != nil {
			return errors.Wrap(err, "failed to decode fee recipient")
		}
		if len(tmp) != bellatrix.ExecutionAddressLength {
			return errors.New("incorrect length for fee recipient")
		}
		var feeRecipient bellatrix.ExecutionAddress
		copy(feeRecipient[:], tmp)
		c.FeeRecipient = &feeRecipient
	}
	if data.GasLimit != "" {
		gasLimit, err := strconv.ParseUint(data.GasLimit, 10, 64)
		if err != nil {
			return errors.Wrap(err, "invalid gas limit")
		}
		c.GasLimit = &gasLimit
	}
	if data.Grace != "" {
		tmp, err := strconv.ParseInt(data.Grace, 10, 64)
		if err != nil {
			return errors.Wrap(err, "grace invalid")
		}
		if tmp < 0 {
			return errors.New("grace cannot be negative")
		}
		grace := time.Duration(tmp) * time.Millisecond
		c.Grace = &grace
	}
	if data.MinValue != "" {
		minValue, err := decimal.NewFromString(data.MinValue)
		if err != nil {
			return errors.Wrap(err, "min value invalid")
		}
		if minValue.Sign() == -1 {
			return errors.New("min value cannot be negative")
		}
		minValue = minValue.Mul(weiPerETH)
		c.MinValue = &minValue
	}

	return nil
}

// String provides a string representation of the struct.
func (c *ProposerRelayConfig) String() string {
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Sprintf("ERR: %v\n", err)
	}
	return string(data)
}
