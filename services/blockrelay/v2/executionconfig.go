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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

var version = 2

var zeroPubkey phase0.BLSPubKey

// ExecutionConfig contains hierarchical configuration for validators
// proposing execution payloads.
type ExecutionConfig struct {
	Version      int
	FeeRecipient *bellatrix.ExecutionAddress
	GasLimit     *uint64
	Grace        *time.Duration
	MinValue     *decimal.Decimal
	Relays       map[string]*BaseRelayConfig
	Proposers    []*ProposerConfig
}

type executionConfigJSON struct {
	Version      int                         `json:"version"`
	FeeRecipient string                      `json:"fee_recipient,omitempty"`
	GasLimit     string                      `json:"gas_limit,omitempty"`
	Grace        string                      `json:"grace,omitempty"`
	MinValue     string                      `json:"min_value,omitempty"`
	Relays       map[string]*BaseRelayConfig `json:"relays,omitempty"`
	Proposers    []*ProposerConfig           `json:"proposers,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (e *ExecutionConfig) MarshalJSON() ([]byte, error) {
	feeRecipient := ""
	if e.FeeRecipient != nil {
		feeRecipient = fmt.Sprintf("%#x", *e.FeeRecipient)
	}
	gasLimit := ""
	if e.GasLimit != nil {
		gasLimit = fmt.Sprintf("%d", *e.GasLimit)
	}
	grace := ""
	if e.Grace != nil {
		grace = fmt.Sprintf("%d", e.Grace.Milliseconds())
	}
	minValue := ""
	if e.MinValue != nil {
		minValue = fmt.Sprintf("%v", e.MinValue.Div(weiPerETH))
	}

	return json.Marshal(&executionConfigJSON{
		Version:      version,
		FeeRecipient: feeRecipient,
		GasLimit:     gasLimit,
		Grace:        grace,
		MinValue:     minValue,
		Relays:       e.Relays,
		Proposers:    e.Proposers,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (e *ExecutionConfig) UnmarshalJSON(input []byte) error {
	var data executionConfigJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	if data.Version != version {
		return fmt.Errorf("unexpected version %d", data.Version)
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
		e.FeeRecipient = &feeRecipient
	}
	if data.GasLimit != "" {
		gasLimit, err := strconv.ParseUint(data.GasLimit, 10, 64)
		if err != nil {
			return errors.Wrap(err, "invalid gas limit")
		}
		e.GasLimit = &gasLimit
	}
	if data.Grace != "" {
		tmp, err := strconv.ParseUint(data.Grace, 10, 64)
		if err != nil {
			return errors.Wrap(err, "grace invalid")
		}
		grace := time.Duration(tmp) * time.Millisecond
		e.Grace = &grace
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
		e.MinValue = &minValue
	}
	e.Relays = data.Relays
	e.Proposers = data.Proposers

	return nil
}

// ProposerConfig returns the proposer configuration for the given validator.
func (e *ExecutionConfig) ProposerConfig(_ context.Context,
	account e2wtypes.Account,
	pubkey phase0.BLSPubKey,
	fallbackFeeRecipient bellatrix.ExecutionAddress,
	fallbackGasLimit uint64,
) (
	*beaconblockproposer.ProposerConfig,
	error,
) {
	config := &beaconblockproposer.ProposerConfig{
		Relays: make([]*beaconblockproposer.RelayConfig, 0),
	}

	if e.FeeRecipient == nil {
		config.FeeRecipient = fallbackFeeRecipient
	} else {
		config.FeeRecipient = *e.FeeRecipient
	}

	// Set initial relay options.
	for address, baseRelayConfig := range e.Relays {
		configRelay := &beaconblockproposer.RelayConfig{
			Address: address,
		}
		if e.Grace == nil {
			configRelay.Grace = 0
		} else {
			configRelay.Grace = *e.Grace
		}
		if e.MinValue == nil {
			configRelay.MinValue = decimal.Zero
		} else {
			configRelay.MinValue = *e.MinValue
		}
		setRelayConfig(configRelay, baseRelayConfig, config.FeeRecipient, fallbackGasLimit)
		config.Relays = append(config.Relays, configRelay)
	}

	// Work through the proposer-specific options to see if one matches.
	var accountName string
	if provider, isProvider := account.(e2wtypes.AccountWalletProvider); isProvider {
		accountName = fmt.Sprintf("%s/%s", provider.Wallet().Name(), account.Name())
	} else {
		accountName = fmt.Sprintf("<unknown>/%s", account.Name())
	}
	for _, proposerConfig := range e.Proposers {
		match := false
		switch {
		case proposerConfig.Account != nil:
			match = proposerConfig.Account.Match([]byte(accountName))
		case !bytes.Equal(proposerConfig.Validator[:], zeroPubkey[:]):
			match = bytes.Equal(proposerConfig.Validator[:], pubkey[:])
		default:
			return nil, errors.New("proposer config without either account or validator; cannot apply")
		}
		if !match {
			continue
		}

		// Update from proposer-level info.
		if proposerConfig.FeeRecipient != nil {
			config.FeeRecipient = *proposerConfig.FeeRecipient
			for _, configRelay := range config.Relays {
				configRelay.FeeRecipient = *proposerConfig.FeeRecipient
			}
		}
		if proposerConfig.GasLimit != nil {
			for _, configRelay := range config.Relays {
				configRelay.GasLimit = *proposerConfig.GasLimit
			}
		}
		if proposerConfig.Grace != nil {
			for _, configRelay := range config.Relays {
				configRelay.Grace = *proposerConfig.Grace
			}
		}
		if proposerConfig.MinValue != nil {
			for _, configRelay := range config.Relays {
				configRelay.MinValue = *proposerConfig.MinValue
			}
		}

		if proposerConfig.ResetRelays {
			// The proposer wants to start from scratch, remove existing relay info.
			config.Relays = make([]*beaconblockproposer.RelayConfig, 0)
		}

		relays := make([]*beaconblockproposer.RelayConfig, 0)

		// Create/update from relay-level info.
		updated := make(map[string]struct{})
		// Update existing relays.
		for _, configRelay := range config.Relays {
			proposerRelayConfig, exists := proposerConfig.Relays[configRelay.Address]
			if exists {
				if !proposerRelayConfig.Disabled {
					updateRelayConfig(configRelay, proposerRelayConfig)
					relays = append(relays, configRelay)
				}
			} else {
				// No update; pass along as-is.
				relays = append(relays, configRelay)
			}
			updated[configRelay.Address] = struct{}{}
		}
		// Add new relays.
		for address, proposerRelayConfig := range proposerConfig.Relays {
			if _, alreadyUpdated := updated[address]; !alreadyUpdated {
				configRelay := &beaconblockproposer.RelayConfig{
					Address: address,
				}
				if e.Grace == nil {
					configRelay.Grace = 0
				} else {
					configRelay.Grace = *e.Grace
				}
				if e.MinValue == nil {
					configRelay.MinValue = decimal.Zero
				} else {
					configRelay.MinValue = *e.MinValue
				}
				setRelayConfig(configRelay, &BaseRelayConfig{}, config.FeeRecipient, fallbackGasLimit)
				updateRelayConfig(configRelay, proposerRelayConfig)
				relays = append(relays, configRelay)
			}
		}
		config.Relays = relays

		// Once we have a match we are done.
		break
	}

	return config, nil
}

// setRelayConfig sets the base configuration for a relay.
func setRelayConfig(config *beaconblockproposer.RelayConfig,
	relayConfig *BaseRelayConfig,
	fallbackFeeRecipient bellatrix.ExecutionAddress,
	fallbackGasLimit uint64,
) {
	if relayConfig.PublicKey != nil {
		config.PublicKey = relayConfig.PublicKey
	}

	if relayConfig.FeeRecipient == nil {
		config.FeeRecipient = fallbackFeeRecipient
	} else {
		config.FeeRecipient = *relayConfig.FeeRecipient
	}

	if relayConfig.GasLimit == nil {
		config.GasLimit = fallbackGasLimit
	} else {
		config.GasLimit = *relayConfig.GasLimit
	}

	if relayConfig.Grace != nil {
		config.Grace = *relayConfig.Grace
	}

	if relayConfig.MinValue != nil {
		config.MinValue = *relayConfig.MinValue
	}
}

// updateRelayConfig updates the configuration for a relay with proposer-specific overrides.
func updateRelayConfig(config *beaconblockproposer.RelayConfig,
	relayConfig *ProposerRelayConfig,
) {
	if relayConfig.PublicKey != nil {
		config.PublicKey = relayConfig.PublicKey
	}

	if relayConfig.FeeRecipient != nil {
		config.FeeRecipient = *relayConfig.FeeRecipient
	}

	if relayConfig.GasLimit != nil {
		config.GasLimit = *relayConfig.GasLimit
	}

	if relayConfig.Grace != nil {
		config.Grace = *relayConfig.Grace
	}

	if relayConfig.MinValue != nil {
		config.MinValue = *relayConfig.MinValue
	}
}

// String provides a string representation of the struct.
func (e *ExecutionConfig) String() string {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Sprintf("ERR: %v\n", err)
	}
	return string(data)
}
