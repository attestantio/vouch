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

package v2

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
)

// ProposerConfig contains proposer-specific configuration for validators
// proposing execution payloads.
type ProposerConfig struct {
	Validator    phase0.BLSPubKey
	Account      *regexp.Regexp
	FeeRecipient *bellatrix.ExecutionAddress
	GasLimit     *uint64
	Grace        *time.Duration
	MinValue     *decimal.Decimal
	Relays       map[string]*ProposerRelayConfig
}

type proposerConfigJSON struct {
	Proposer     string                          `json:"proposer"`
	FeeRecipient string                          `json:"fee_recipient,omitempty"`
	GasLimit     string                          `json:"gas_limit,omitempty"`
	Grace        string                          `json:"grace,omitempty"`
	MinValue     string                          `json:"min_value,omitempty"`
	Relays       map[string]*ProposerRelayConfig `json:"relays,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (p *ProposerConfig) MarshalJSON() ([]byte, error) {
	proposer := ""
	if p.Account != nil {
		proposer = p.Account.String()
	} else {
		proposer = fmt.Sprintf("%#x", p.Validator)
	}
	feeRecipient := ""
	if p.FeeRecipient != nil {
		feeRecipient = fmt.Sprintf("%#x", *p.FeeRecipient)
	}
	gasLimit := ""
	if p.GasLimit != nil {
		gasLimit = fmt.Sprintf("%d", *p.GasLimit)
	}
	grace := ""
	if p.Grace != nil {
		grace = fmt.Sprintf("%d", p.Grace.Milliseconds())
	}
	minValue := ""
	if p.MinValue != nil {
		minValue = fmt.Sprintf("%v", p.MinValue.Div(weiPerETH))
	}

	return json.Marshal(&proposerConfigJSON{
		Proposer:     proposer,
		FeeRecipient: feeRecipient,
		GasLimit:     gasLimit,
		Grace:        grace,
		MinValue:     minValue,
		Relays:       p.Relays,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *ProposerConfig) UnmarshalJSON(input []byte) error {
	var data proposerConfigJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	if data.Proposer == "" {
		return errors.New("proposer is missing")
	}
	if strings.HasPrefix(data.Proposer, "0x") {
		tmp, err := hex.DecodeString(strings.TrimPrefix(data.Proposer, "0x"))
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to decode proposer %s", data.Proposer))
		}
		if len(tmp) != phase0.PublicKeyLength {
			return fmt.Errorf("incorrect length for proposer %s", data.Proposer)
		}
		copy(p.Validator[:], tmp)
	} else {
		account, err := regexp.Compile(data.Proposer)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("invalid account proposer %s", data.Proposer))
		}
		p.Account = account
	}
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
		p.FeeRecipient = &feeRecipient
	}
	if data.GasLimit != "" {
		gasLimit, err := strconv.ParseUint(data.GasLimit, 10, 64)
		if err != nil {
			return errors.Wrap(err, "invalid gas limit")
		}
		p.GasLimit = &gasLimit
	}
	if data.Grace != "" {
		tmp, err := strconv.ParseUint(data.Grace, 10, 64)
		if err != nil {
			return errors.Wrap(err, "grace invalid")
		}
		grace := time.Duration(tmp) * time.Millisecond
		p.Grace = &grace
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
		p.MinValue = &minValue
	}
	p.Relays = data.Relays

	return nil
}

func (p *ProposerConfig) String() string {
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Sprintf("ERR: %v\n", err)
	}
	return string(data)
}
