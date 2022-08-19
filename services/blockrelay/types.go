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
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// BoostConfig is the configuration for MEV-boost-enabled validators.
type BoostConfig struct {
	ProposerConfigs map[phase0.BLSPubKey]*ProposerConfig
	DefaultConfig   *ProposerConfig
}

type boostConfigJSON struct {
	ProposerConfigs map[string]*ProposerConfig `json:"proposer_config,omitempty"`
	DefaultConfig   *ProposerConfig            `json:"default_config,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (b *BoostConfig) MarshalJSON() ([]byte, error) {
	proposerConfigs := make(map[string]*ProposerConfig)
	for addr, proposerConfig := range b.ProposerConfigs {
		proposerConfigs[fmt.Sprintf("%#x", addr)] = proposerConfig
	}

	return json.Marshal(&boostConfigJSON{
		ProposerConfigs: proposerConfigs,
		DefaultConfig:   b.DefaultConfig,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BoostConfig) UnmarshalJSON(input []byte) error {
	var data boostConfigJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	proposerConfigs := make(map[phase0.BLSPubKey]*ProposerConfig, len(data.ProposerConfigs))
	for key, config := range data.ProposerConfigs {
		pubkey, err := hex.DecodeString(strings.TrimPrefix(key, "0x"))
		if err != nil {
			return errors.Wrap(err, "failed to decode public key")
		}
		pubKey := phase0.BLSPubKey{}
		copy(pubKey[:], pubkey)
		proposerConfigs[pubKey] = config
	}
	b.ProposerConfigs = proposerConfigs

	b.DefaultConfig = data.DefaultConfig

	return nil
}

// String provides a string representation of the struct.
func (b *BoostConfig) String() string {
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Sprintf("ERR: %v\n", err)
	}
	return string(data)
}

// ProposerConfig is the configuration for a specific proposer.
type ProposerConfig struct {
	FeeRecipient bellatrix.ExecutionAddress
	Builder      *BuilderConfig
}

type proposerConfigJSON struct {
	FeeRecipient string         `json:"fee_recipient"`
	Builder      *BuilderConfig `json:"builder"`
}

// MarshalJSON implements json.Marshaler.
func (p *ProposerConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(&proposerConfigJSON{
		FeeRecipient: fmt.Sprintf("%#x", p.FeeRecipient),
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

// BuilderConfig is the builder configuration for a specific proposer.
type BuilderConfig struct {
	Enabled  bool
	Relays   []string
	GasLimit uint64
}

type builderConfigJSON struct {
	Enabled  bool     `json:"enabled"`
	Relays   []string `json:"relays,omitempty"`
	GasLimit string   `json:"gas_limit"`
}

// MarshalJSON implements json.Marshaler.
func (b *BuilderConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(&builderConfigJSON{
		Enabled:  b.Enabled,
		Relays:   b.Relays,
		GasLimit: fmt.Sprintf("%d", b.GasLimit),
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BuilderConfig) UnmarshalJSON(input []byte) error {
	var data builderConfigJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	b.Enabled = data.Enabled
	b.Relays = data.Relays
	var err error
	b.GasLimit, err = strconv.ParseUint(data.GasLimit, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid gas limit")
	}

	return nil
}

// String provides a string representation of the struct.
func (b *BuilderConfig) String() string {
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Sprintf("ERR: %v\n", err)
	}
	return string(data)
}
