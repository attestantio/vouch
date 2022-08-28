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

package blockrelay

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/pkg/errors"
)

// ProposerConfig is the configuration for a specific proposer.
type ProposerConfig struct {
	FeeRecipient bellatrix.ExecutionAddress
	GasLimit     uint64
	Builder      *BuilderConfig
}

type proposerConfigJSON struct {
	FeeRecipient string         `json:"fee_recipient"`
	GasLimit     string         `json:"gas_limit"`
	Builder      *BuilderConfig `json:"builder"`
}

// MarshalJSON implements json.Marshaler.
func (p *ProposerConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(&proposerConfigJSON{
		FeeRecipient: fmt.Sprintf("%#x", p.FeeRecipient),
		GasLimit:     fmt.Sprintf("%d", p.GasLimit),
		Builder:      p.Builder,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *ProposerConfig) UnmarshalJSON(input []byte) error {
	var data proposerConfigJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	feeRecipient, err := hex.DecodeString(strings.TrimPrefix(data.FeeRecipient, "0x"))
	if err != nil {
		return errors.Wrap(err, "failed to decode fee recipient")
	}
	copy(p.FeeRecipient[:], feeRecipient)
	p.GasLimit, err = strconv.ParseUint(data.GasLimit, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid gas limit")
	}
	p.Builder = data.Builder

	return nil
}

// String provides a string representation of the struct.
func (p *ProposerConfig) String() string {
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Sprintf("ERR: %v\n", err)
	}
	return string(data)
}
