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
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// ExecutionConfig is the execution configuration for validators.
type ExecutionConfig struct {
	ProposerConfigs map[phase0.BLSPubKey]*ProposerConfig
	DefaultConfig   *ProposerConfig
}

type executionConfigJSON struct {
	ProposerConfigs map[string]*ProposerConfig `json:"proposer_config,omitempty"`
	DefaultConfig   *ProposerConfig            `json:"default_config,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (e *ExecutionConfig) MarshalJSON() ([]byte, error) {
	proposerConfigs := make(map[string]*ProposerConfig)
	for addr, proposerConfig := range e.ProposerConfigs {
		proposerConfigs[fmt.Sprintf("%#x", addr)] = proposerConfig
	}

	return json.Marshal(&executionConfigJSON{
		ProposerConfigs: proposerConfigs,
		DefaultConfig:   e.DefaultConfig,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (e *ExecutionConfig) UnmarshalJSON(input []byte) error {
	var data executionConfigJSON
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
	e.ProposerConfigs = proposerConfigs

	e.DefaultConfig = data.DefaultConfig

	return nil
}

// ProposerConfig provides the proposer configuration for a given public key.
func (e *ExecutionConfig) ProposerConfig(pubkey phase0.BLSPubKey,
) *ProposerConfig {
	if _, exists := e.ProposerConfigs[pubkey]; exists {
		return e.ProposerConfigs[pubkey]
	}
	return e.DefaultConfig
}

// String provides a string representation of the struct.
func (e *ExecutionConfig) String() string {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Sprintf("ERR: %v\n", err)
	}
	return string(data)
}
