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
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
)

type ProposerRelayConfig struct {
	Disabled     bool
	FeeRecipient *bellatrix.ExecutionAddress
	GasLimit     *uint64
	Grace        *time.Duration
	MinValue     *decimal.Decimal
}

type proposerRelayConfigJSON struct {
	Disabled     bool   `json:"disabled,omitempty"`
	FeeRecipient string `json:"fee_recipient,omitempty"`
	GasLimit     string `json:"gas_limit,omitempty"`
	Grace        string `json:"grace,omitempty"`
	MinValue     string `json:"min_value,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (c *ProposerRelayConfig) MarshalJSON() ([]byte, error) {
	feeRecipient := ""
	if c.FeeRecipient != nil {
		feeRecipient = fmt.Sprintf("%#x", *c.FeeRecipient)
	}
	gasLimit := ""
	if c.GasLimit != nil {
		gasLimit = fmt.Sprintf("%d", *c.GasLimit)
	}
	grace := ""
	if c.Grace != nil {
		grace = fmt.Sprintf("%d", c.Grace.Milliseconds())
	}
	minValue := ""
	if c.MinValue != nil {
		minValue = fmt.Sprintf("%v", c.MinValue.Div(weiPerETH))
	}
	return json.Marshal(&proposerRelayConfigJSON{
		Disabled:     c.Disabled,
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
	if data.FeeRecipient != "" {
		tmp, err := hex.DecodeString(strings.TrimPrefix(data.FeeRecipient, "0x"))
		if err != nil {
			return errors.Wrap(err, "failed to decode fee recipient")
		}
		if len(tmp) != bellatrix.ExecutionAddressLength {
			return errors.New("incorrect length for fee recipient")
		}
		feeRecipient := bellatrix.ExecutionAddress{}
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
		tmp, err := strconv.ParseUint(data.Grace, 10, 64)
		if err != nil {
			return errors.Wrap(err, "grace invalid")
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
