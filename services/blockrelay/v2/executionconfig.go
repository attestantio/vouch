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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	Version           int
	FeeRecipient      *bellatrix.ExecutionAddress
	GasLimit          *uint64
	Grace             *time.Duration
	MinValue          *decimal.Decimal
	EPBSBuilderConfig *EPBSBuilderConfig
	Relays            map[string]*BaseRelayConfig
	Proposers         []*ProposerConfig
}

type executionConfigJSON struct {
	Version           int                         `json:"version"`
	FeeRecipient      string                      `json:"fee_recipient,omitempty"`
	GasLimit          string                      `json:"gas_limit,omitempty"`
	Grace             string                      `json:"grace,omitempty"`
	MinValue          string                      `json:"min_value,omitempty"`
	EPBSBuilderConfig *EPBSBuilderConfig          `json:"epbs_builder_config,omitempty"`
	Relays            map[string]*BaseRelayConfig `json:"relays,omitempty"`
	Proposers         []*ProposerConfig           `json:"proposers,omitempty"`
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
		Version:           version,
		FeeRecipient:      feeRecipient,
		GasLimit:          gasLimit,
		Grace:             grace,
		MinValue:          minValue,
		EPBSBuilderConfig: e.EPBSBuilderConfig,
		Relays:            e.Relays,
		Proposers:         e.Proposers,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (e *ExecutionConfig) UnmarshalJSON(input []byte) error {
	var data executionConfigJSON
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
	for i, proposer := range data.Proposers {
		if proposer == nil {
			return errors.Errorf("invalid JSON: proposer %d is null", i)
		}
	}

	if data.Version != version {
		return fmt.Errorf("unexpected version %d", data.Version)
	}

	var err error
	if e.FeeRecipient, err = parseFeeRecipient(data.FeeRecipient); err != nil {
		return err
	}
	if e.GasLimit, err = parseGasLimit(data.GasLimit); err != nil {
		return err
	}
	if e.Grace, err = parseGrace(data.Grace); err != nil {
		return err
	}
	if e.MinValue, err = parseMinValue(data.MinValue); err != nil {
		return err
	}
	e.EPBSBuilderConfig = data.EPBSBuilderConfig
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
	fallbackMinBid phase0.Gwei,
	fallbackBuilderBoostFactor uint64,
) (
	*beaconblockproposer.ProposerConfig,
	error,
) {
	// Set base configuration without relays.
	config := &beaconblockproposer.ProposerConfig{
		EPBSBuilderConfig: &beaconblockproposer.EPBSBuilderConfig{
			MinBid:             fallbackMinBid,
			BuilderBoostFactor: fallbackBuilderBoostFactor,
			Builders:           make([]*beaconblockproposer.EPBSBuilder, 0),
		},
		Relays: make([]*beaconblockproposer.RelayConfig, 0),
	}
	if e.FeeRecipient == nil {
		config.FeeRecipient = fallbackFeeRecipient
	} else {
		config.FeeRecipient = *e.FeeRecipient
	}
	if e.GasLimit == nil {
		config.GasLimit = fallbackGasLimit
	} else {
		config.GasLimit = *e.GasLimit
	}

	e.setInitialRelayOptions(ctx, config, fallbackGasLimit)

	proposerConfig, err := e.setProposerSpecificOptions(ctx, config, account, pubkey, fallbackFeeRecipient, fallbackGasLimit)
	if err != nil {
		return nil, err
	}
	e.resolveEPBSBuilderConfig(config.EPBSBuilderConfig, proposerConfig)

	return config, nil
}

// HasMinValueWithoutEPBSMinBid returns true if a min_value is set where no ePBS min_bid resolves.
// A proposer min_value is covered only by the proposer's own min_bid: inheriting the root min_bid would drop
// the proposer-specific floor.
// From Gloas onwards min_value applies only to relays, so the operator may expect a floor that is not applied.
func (e *ExecutionConfig) HasMinValueWithoutEPBSMinBid() bool {
	if e.MinValue != nil && !hasEPBSMinBid(e.EPBSBuilderConfig) {
		return true
	}
	for _, proposer := range e.Proposers {
		if proposer != nil && proposer.MinValue != nil && !hasEPBSMinBid(proposer.EPBSBuilderConfig) {
			return true
		}
	}

	return false
}

func hasEPBSMinBid(config *EPBSBuilderConfig) bool {
	return config != nil && config.MinBid != nil
}

// resolveEPBSBuilderConfig applies the root and then the matching proposer's ePBS policy.
// Entries resolve last so that omitted fields inherit the proposer's values.
func (e *ExecutionConfig) resolveEPBSBuilderConfig(config *beaconblockproposer.EPBSBuilderConfig, proposerConfig *ProposerConfig) {
	var root, proposer EPBSBuilderConfig
	if e.EPBSBuilderConfig != nil {
		root = *e.EPBSBuilderConfig
	}
	if proposerConfig != nil && proposerConfig.EPBSBuilderConfig != nil {
		proposer = *proposerConfig.EPBSBuilderConfig
	}
	config.MinBid = firstSet(config.MinBid, proposer.MinBid, root.MinBid)
	config.BuilderBoostFactor = firstSet(config.BuilderBoostFactor, proposer.BuilderBoostFactor, root.BuilderBoostFactor)
	config.Builders = resolvedEPBSBuilders(firstSet(nil, proposer.Builders, root.Builders), config.MinBid, config.BuilderBoostFactor)
}

func resolvedEPBSBuilders(builders []*EPBSBuilder, minBid phase0.Gwei, builderBoostFactor uint64) []*beaconblockproposer.EPBSBuilder {
	res := make([]*beaconblockproposer.EPBSBuilder, len(builders))
	for i, builder := range builders {
		if builder == nil {
			continue
		}
		res[i] = &beaconblockproposer.EPBSBuilder{
			URL:                 builder.URL,
			AuthData:            append([]byte(nil), builder.AuthData...),
			BuilderPubkeys:      append([]phase0.BLSPubKey(nil), builder.BuilderPubkeys...),
			MaxExecutionPayment: builder.MaxExecutionPayment,
			MinBid:              firstSet(minBid, builder.MinBid),
			BuilderBoostFactor:  firstSet(builderBoostFactor, builder.BuilderBoostFactor),
		}
	}

	return res
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
) (
	*ProposerConfig,
	error,
) {
	accountName := setAccountName(account)

	// Work through the proposer-specific configurations to see if one matches.
	for i, proposerConfig := range e.Proposers {
		if proposerConfig == nil {
			return nil, errors.Errorf("proposer config %d is null", i)
		}
		var match bool
		switch {
		case proposerConfig.Account != nil:
			match = proposerConfig.Account.MatchString(accountName)
		case !bytes.Equal(proposerConfig.Validator[:], zeroPubkey[:]):
			match = bytes.Equal(proposerConfig.Validator[:], pubkey[:])
		default:
			return nil, errors.New("proposer config without either account or validator; cannot apply")
		}
		if !match {
			continue
		}

		e.setProposerConfigOptions(ctx, config, proposerConfig, fallbackFeeRecipient, fallbackGasLimit)

		// Once we have a match we are done.
		return proposerConfig, nil
	}

	return nil, nil
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
		config.GasLimit = *proposerConfig.GasLimit
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

	relayConfig.FeeRecipient = firstSet(fallbackFeeRecipient, proposerRelayConfig.FeeRecipient, proposerConfig.FeeRecipient, e.FeeRecipient)
	relayConfig.Grace = firstSet(0, proposerRelayConfig.Grace, proposerConfig.Grace, e.Grace)
	relayConfig.GasLimit = firstSet(fallbackGasLimit, proposerRelayConfig.GasLimit, proposerConfig.GasLimit, e.GasLimit)
	relayConfig.MinValue = firstSet(decimal.Zero, proposerRelayConfig.MinValue, proposerConfig.MinValue, e.MinValue)

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
