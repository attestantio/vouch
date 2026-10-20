// Copyright © 2022 - 2026 Attestant Limited.
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
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
)

// ProposerConfig contains proposer-specific configuration for validators
// proposing execution payloads.
type ProposerConfig struct {
	Validator         phase0.BLSPubKey
	Account           *regexp.Regexp
	FeeRecipient      *bellatrix.ExecutionAddress
	GasLimit          *uint64
	Grace             *time.Duration
	MinValue          *decimal.Decimal
	EPBSBuilderConfig *EPBSBuilderConfig
	ResetRelays       bool
	Relays            map[string]*ProposerRelayConfig
}

type proposerConfigJSON struct {
	Proposer          string                          `json:"proposer"`
	FeeRecipient      string                          `json:"fee_recipient,omitempty"`
	GasLimit          string                          `json:"gas_limit,omitempty"`
	Grace             string                          `json:"grace,omitempty"`
	MinValue          string                          `json:"min_value,omitempty"`
	EPBSBuilderConfig *EPBSBuilderConfig              `json:"epbs_builder_config,omitempty"`
	ResetRelays       bool                            `json:"reset_relays,omitempty"`
	Relays            map[string]*ProposerRelayConfig `json:"relays,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (p *ProposerConfig) MarshalJSON() ([]byte, error) {
	var proposer string
	if p.Account != nil {
		proposer = p.Account.String()
	} else {
		proposer = fmt.Sprintf("%#x", p.Validator)
	}
	var feeRecipient string
	if p.FeeRecipient != nil {
		feeRecipient = fmt.Sprintf("%#x", *p.FeeRecipient)
	}
	var gasLimit string
	if p.GasLimit != nil {
		gasLimit = fmt.Sprintf("%d", *p.GasLimit)
	}
	var grace string
	if p.Grace != nil {
		grace = fmt.Sprintf("%d", p.Grace.Milliseconds())
	}
	var minValue string
	if p.MinValue != nil {
		minValue = fmt.Sprintf("%v", p.MinValue.Div(weiPerETH))
	}

	return json.Marshal(&proposerConfigJSON{
		Proposer:          proposer,
		FeeRecipient:      feeRecipient,
		GasLimit:          gasLimit,
		Grace:             grace,
		MinValue:          minValue,
		EPBSBuilderConfig: p.EPBSBuilderConfig,
		ResetRelays:       p.ResetRelays,
		Relays:            p.Relays,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *ProposerConfig) UnmarshalJSON(input []byte) error {
	var data proposerConfigJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(input, &fields); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	if isNullField(fields, "epbs_builder_config") {
		return errors.New("invalid JSON: ePBS builder config must be an object")
	}

	var err error
	if p.Validator, p.Account, err = parseProposer(data.Proposer); err != nil {
		return err
	}
	if p.FeeRecipient, err = parseFeeRecipient(data.FeeRecipient); err != nil {
		return err
	}
	if p.GasLimit, err = parseGasLimit(data.GasLimit); err != nil {
		return err
	}
	if p.Grace, err = parseGrace(data.Grace); err != nil {
		return err
	}
	if p.MinValue, err = parseMinValue(data.MinValue); err != nil {
		return err
	}
	p.EPBSBuilderConfig = data.EPBSBuilderConfig
	p.ResetRelays = data.ResetRelays
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
