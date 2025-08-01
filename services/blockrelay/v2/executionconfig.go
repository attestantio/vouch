// Copyright © 2022, 2024 Attestant Limited.
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
	var feeRecipient string
	if e.FeeRecipient != nil {
		feeRecipient = fmt.Sprintf("%#x", *e.FeeRecipient)
	}
	var gasLimit string
	if e.GasLimit != nil {
		gasLimit = fmt.Sprintf("%d", *e.GasLimit)
	}
	var grace string
	if e.Grace != nil {
		grace = fmt.Sprintf("%d", e.Grace.Milliseconds())
	}
	var minValue string
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
		tmp, err := strconv.ParseInt(data.Grace, 10, 64)
		if err != nil {
			return errors.Wrap(err, "grace invalid")
		}
		if tmp < 0 {
			return errors.New("grace cannot be negative")
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
func (e *ExecutionConfig) ProposerConfig(ctx context.Context,
	account e2wtypes.Account,
	pubkey phase0.BLSPubKey,
	fallbackFeeRecipient bellatrix.ExecutionAddress,
	fallbackGasLimit uint64,
) (
	*beaconblockproposer.ProposerConfig,
	error,
) {
	// Set base configuration without relays.
	config := &beaconblockproposer.ProposerConfig{
		Relays: make([]*beaconblockproposer.RelayConfig, 0),
	}
	if e.FeeRecipient == nil {
		config.FeeRecipient = fallbackFeeRecipient
	} else {
		config.FeeRecipient = *e.FeeRecipient
	}

	e.setInitialRelayOptions(ctx, config, fallbackGasLimit)

	if err := e.setProposerSpecificOptions(ctx, config, account, pubkey, fallbackFeeRecipient, fallbackGasLimit); err != nil {
		return nil, err
	}

	return config, nil
}

func (e *ExecutionConfig) setInitialRelayOptions(_ context.Context,
	config *beaconblockproposer.ProposerConfig,
	fallbackGasLimit uint64,
) {
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
		if e.GasLimit == nil {
			setRelayConfig(configRelay, baseRelayConfig, config.FeeRecipient, fallbackGasLimit)
		} else {
			setRelayConfig(configRelay, baseRelayConfig, config.FeeRecipient, *e.GasLimit)
		}
		config.Relays = append(config.Relays, configRelay)
	}
}

func (e *ExecutionConfig) setProposerSpecificOptions(ctx context.Context,
	config *beaconblockproposer.ProposerConfig,
	account e2wtypes.Account,
	pubkey phase0.BLSPubKey,
	fallbackFeeRecipient bellatrix.ExecutionAddress,
	fallbackGasLimit uint64,
) error {
	accountName := setAccountName(account)

	// Work through the proposer-specific configurations to see if one matches.
	for _, proposerConfig := range e.Proposers {
		var match bool
		switch {
		case proposerConfig.Account != nil:
			match = proposerConfig.Account.MatchString(accountName)
		case !bytes.Equal(proposerConfig.Validator[:], zeroPubkey[:]):
			match = bytes.Equal(proposerConfig.Validator[:], pubkey[:])
		default:
			return errors.New("proposer config without either account or validator; cannot apply")
		}
		if !match {
			continue
		}

		e.setProposerConfigOptions(ctx, config, proposerConfig, fallbackFeeRecipient, fallbackGasLimit)

		// Once we have a match we are done.
		break
	}

	return nil
}

func setAccountName(account e2wtypes.Account) string {
	if account == nil {
		return "<unknown>/<unknown>"
	}

	if provider, isProvider := account.(e2wtypes.AccountWalletProvider); isProvider {
		return fmt.Sprintf("%s/%s", provider.Wallet().Name(), account.Name())
	}

	return fmt.Sprintf("<unknown>/%s", account.Name())
}

func (e *ExecutionConfig) setProposerConfigOptions(_ context.Context,
	config *beaconblockproposer.ProposerConfig,
	proposerConfig *ProposerConfig,
	fallbackFeeRecipient bellatrix.ExecutionAddress,
	fallbackGasLimit uint64,
) {
	// Update from proposer-specific configuration.
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
			relays = append(relays, e.generateRelayConfig(address, proposerConfig, proposerRelayConfig, fallbackFeeRecipient, fallbackGasLimit))
		}
	}
	config.Relays = relays
}

// generateRelayConfig generates a relay configuration from the various
// tiers of existing information.
func (e *ExecutionConfig) generateRelayConfig(
	address string,
	proposerConfig *ProposerConfig,
	proposerRelayConfig *ProposerRelayConfig,
	fallbackFeeRecipient bellatrix.ExecutionAddress,
	fallbackGasLimit uint64,
) *beaconblockproposer.RelayConfig {
	relayConfig := &beaconblockproposer.RelayConfig{
		Address:   address,
		PublicKey: proposerRelayConfig.PublicKey,
	}

	switch {
	case proposerRelayConfig.FeeRecipient != nil:
		// Fetch from proposer relay config.
		relayConfig.FeeRecipient = *proposerRelayConfig.FeeRecipient
	case proposerConfig.FeeRecipient != nil:
		// Fetch from proposer config.
		relayConfig.FeeRecipient = *proposerConfig.FeeRecipient
	case e.FeeRecipient != nil:
		// Fetch from execution config.
		relayConfig.FeeRecipient = *e.FeeRecipient
	default:
		// No value; set to default.
		relayConfig.FeeRecipient = fallbackFeeRecipient
	}

	switch {
	case proposerRelayConfig.Grace != nil:
		// Fetch from proposer relay config.
		relayConfig.Grace = *proposerRelayConfig.Grace
	case proposerConfig.Grace != nil:
		// Fetch from proposer config.
		relayConfig.Grace = *proposerConfig.Grace
	case e.Grace != nil:
		// Fetch from execution config.
		relayConfig.Grace = *e.Grace
	default:
		// No value; set to zero.
		relayConfig.Grace = 0
	}

	switch {
	case proposerRelayConfig.GasLimit != nil:
		// Fetch from proposer relay config.
		relayConfig.GasLimit = *proposerRelayConfig.GasLimit
	case proposerConfig.GasLimit != nil:
		// Fetch from proposer config.
		relayConfig.GasLimit = *proposerConfig.GasLimit
	case e.GasLimit != nil:
		// Fetch from execution config.
		relayConfig.GasLimit = *e.GasLimit
	default:
		// No value; set to default.
		relayConfig.GasLimit = fallbackGasLimit
	}

	switch {
	case relayConfig.MinValue.Sign() == 1:
		// Already set; nothing to do.
	case proposerRelayConfig.MinValue != nil:
		// Fetch from proposer relay config.
		relayConfig.MinValue = *proposerRelayConfig.MinValue
	case proposerConfig.MinValue != nil:
		// Fetch from proposer config.
		relayConfig.MinValue = *proposerConfig.MinValue
	case e.MinValue != nil:
		// Fetch from execution config.
		relayConfig.MinValue = *e.MinValue
	default:
		// No value; set to zero.
		relayConfig.MinValue = decimal.Zero
	}

	return relayConfig
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
