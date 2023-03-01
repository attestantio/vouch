// Copyright © 2022, 2023 Attestant Limited.
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

package v1

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
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
		var pubKey phase0.BLSPubKey
		if len(pubkey) != len(pubKey) {
			return fmt.Errorf("public key has %d bytes, should have %d", len(pubkey), len(pubKey))
		}

		copy(pubKey[:], pubkey)
		proposerConfigs[pubKey] = config
	}
	e.ProposerConfigs = proposerConfigs

	if data.DefaultConfig == nil {
		return errors.New("default config missing")
	}
	e.DefaultConfig = data.DefaultConfig

	return nil
}

// ProposerConfig returns the proposer configuration for a given validator.
func (e *ExecutionConfig) ProposerConfig(_ context.Context,
	_ e2wtypes.Account,
	pubkey phase0.BLSPubKey,
	fallbackFeeRecipient bellatrix.ExecutionAddress,
	fallbackGasLimit uint64,
) (
	*beaconblockproposer.ProposerConfig,
	error,
) {
	// Try proposer-specific config.
	proposerConfig, exists := e.ProposerConfigs[pubkey]
	if !exists {
		// Try default config.
		proposerConfig = e.DefaultConfig
	}
	if proposerConfig == nil {
		// Use fallback config.
		proposerConfig = &ProposerConfig{
			FeeRecipient: fallbackFeeRecipient,
			GasLimit:     fallbackGasLimit,
			Builder: &BuilderConfig{
				Enabled: false,
			},
		}
	}

	// At this point we definitely have a proposer config, however
	// if it was the default config it is possible that some elements
	// are missing.  Fill them in here.
	if proposerConfig.GasLimit == 0 {
		proposerConfig.GasLimit = fallbackGasLimit
	}
	if proposerConfig.Builder == nil {
		proposerConfig.Builder = &BuilderConfig{}
	}

	relays := make([]*beaconblockproposer.RelayConfig, 0)
	if proposerConfig.Builder.Enabled {
		for _, relayAddress := range proposerConfig.Builder.Relays {
			relays = append(relays, &beaconblockproposer.RelayConfig{
				Address:      relayAddress,
				FeeRecipient: proposerConfig.FeeRecipient,
				GasLimit:     proposerConfig.GasLimit,
				Grace:        proposerConfig.Builder.Grace,
				// MinValue is not available in V1.
				MinValue: decimal.Zero,
			})
		}
	}

	return &beaconblockproposer.ProposerConfig{
		FeeRecipient: proposerConfig.FeeRecipient,
		Relays:       relays,
	}, nil
}

// String provides a string representation of the struct.
func (e *ExecutionConfig) String() string {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Sprintf("ERR: %v\n", err)
	}
	return string(data)
}
