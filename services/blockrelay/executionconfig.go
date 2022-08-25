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
func (b *ExecutionConfig) MarshalJSON() ([]byte, error) {
	proposerConfigs := make(map[string]*ProposerConfig)
	for addr, proposerConfig := range b.ProposerConfigs {
		proposerConfigs[fmt.Sprintf("%#x", addr)] = proposerConfig
	}

	return json.Marshal(&executionConfigJSON{
		ProposerConfigs: proposerConfigs,
		DefaultConfig:   b.DefaultConfig,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *ExecutionConfig) UnmarshalJSON(input []byte) error {
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
	b.ProposerConfigs = proposerConfigs

	b.DefaultConfig = data.DefaultConfig

	return nil
}

// String provides a string representation of the struct.
func (b *ExecutionConfig) String() string {
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Sprintf("ERR: %v\n", err)
	}
	return string(data)
}
