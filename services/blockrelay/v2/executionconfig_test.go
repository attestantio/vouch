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

package v2_test

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	v2 "github.com/attestantio/vouch/services/blockrelay/v2"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"gotest.tools/assert"
)

func TestExecutionConfig(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		err   string
	}{
		{
			name: "Empty",
			err:  "unexpected end of JSON input",
		},
		{
			name:  "JSONBad",
			input: []byte("[]"),
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type v2.executionConfigJSON",
		},
		{
			name:  "VersionMissing",
			input: []byte(`{"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "unexpected version 0",
		},
		{
			name:  "VersionWrongType",
			input: []byte(`{"version":true,"proposer":true,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field executionConfigJSON.version of type int",
		},
		{
			name:  "VersionIncorrect",
			input: []byte(`{"version":1,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "unexpected version 1",
		},
		{
			name:  "FeeRecipientWrongType",
			input: []byte(`{"version":2,"fee_recipient":true,"gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field executionConfigJSON.fee_recipient of type string",
		},
		{
			name:  "FeeRecipientInvalid",
			input: []byte(`{"version":2,"fee_recipient":"true","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "failed to decode fee recipient: encoding/hex: invalid byte: U+0074 't'",
		},
		{
			name:  "FeeRecipientIncorrectLength",
			input: []byte(`{"version":2,"fee_recipient":"0x11111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "incorrect length for fee recipient",
		},
		{
			name:  "GasLimitWrongType",
			input: []byte(`{"version":2,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":true,"grace":"1000","min_value":"0.5"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field executionConfigJSON.gas_limit of type string",
		},
		{
			name:  "GasLimitInvalid",
			input: []byte(`{"version":2,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"true","grace":"1000","min_value":"0.5"}`),
			err:   "invalid gas limit: strconv.ParseUint: parsing \"true\": invalid syntax",
		},
		{
			name:  "GasLimitNegative",
			input: []byte(`{"version":2,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"-1","grace":"1000","min_value":"0.5"}`),
			err:   "invalid gas limit: strconv.ParseUint: parsing \"-1\": invalid syntax",
		},
		{
			name:  "GraceWrongType",
			input: []byte(`{"version":2,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":true,"min_value":"0.5"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field executionConfigJSON.grace of type string",
		},
		{
			name:  "GraceInvalid",
			input: []byte(`{"version":2,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"true","min_value":"0.5"}`),
			err:   "grace invalid: strconv.ParseInt: parsing \"true\": invalid syntax",
		},
		{
			name:  "GraceNegative",
			input: []byte(`{"version":2,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"-1","min_value":"0.5"}`),
			err:   "grace cannot be negative",
		},
		{
			name:  "MinValueWrongType",
			input: []byte(`{"version":2,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":true}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field executionConfigJSON.min_value of type string",
		},
		{
			name:  "MinValueInvalid",
			input: []byte(`{"version":2,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"true"}`),
			err:   "min value invalid: can't convert true to decimal: exponent is not numeric",
		},
		{
			name:  "MinValueNegative",
			input: []byte(`{"version":2,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"-1"}`),
			err:   "min value cannot be negative",
		},
		{
			name:  "Good",
			input: []byte(`{"version":2,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
		},
		{
			name:  "GoodPubkey",
			input: []byte(`{"version":2,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
		},
		{
			name:  "ProposerNull",
			input: []byte(`{"version":2,"proposers":[null]}`),
			err:   "invalid JSON: proposer 0 is null",
		},
		{
			name:  "EPBSBuilderConfigNull",
			input: []byte(`{"version":2,"epbs_builder_config":null}`),
			err:   "invalid JSON: ePBS builder config must be an object",
		},
		{
			name:  "EPBSBuilderConfig",
			input: []byte(`{"version":2,"epbs_builder_config":{"min_bid":"10000000","builder_boost_factor":100,"builders":[]}}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res v2.ExecutionConfig
			err := json.Unmarshal(test.input, &res)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				rt := res.String()
				assert.Equal(t, string(test.input), rt)
			}
		})
	}
}

func TestExecutionConfigRedactsEPBSAuthData(t *testing.T) {
	input := []byte(`{"version":2,"epbs_builder_config":{"builders":[{"url":"https://builder.example","auth_data":"0x1234","builder_pubkeys":[],"max_execution_payment":"0","min_bid":"10000000","builder_boost_factor":100}]}}`)

	var config v2.ExecutionConfig
	require.NoError(t, json.Unmarshal(input, &config))

	output, err := json.Marshal(&config)
	require.NoError(t, err)
	require.NotContains(t, string(output), "0x1234")
	require.Contains(t, string(output), `"auth_data":"redacted"`)
	require.False(t, strings.Contains(config.String(), "0x1234"))
}

func TestExecutionConfigDefaultsEPBSPolicy(t *testing.T) {
	config := &v2.ExecutionConfig{}

	proposerConfig, err := config.ProposerConfig(context.Background(), nil, phase0.BLSPubKey{}, bellatrix.ExecutionAddress{}, 30_000_000, 0, 100)
	require.NoError(t, err)
	output, err := json.Marshal(proposerConfig)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(output, &decoded))
	epbsConfig, exists := decoded["epbs_builder_config"].(map[string]any)
	require.True(t, exists)
	require.Equal(t, "0", epbsConfig["min_bid"])
	require.Equal(t, float64(100), epbsConfig["builder_boost_factor"])
	require.Empty(t, epbsConfig["builders"])
}

func TestExecutionConfigPreservesNilBuilderForRequestValidation(t *testing.T) {
	builders := []*v2.EPBSBuilder{nil}
	config := &v2.ExecutionConfig{EPBSBuilderConfig: &v2.EPBSBuilderConfig{Builders: &builders}}

	proposerConfig, err := config.ProposerConfig(context.Background(), nil, phase0.BLSPubKey{}, bellatrix.ExecutionAddress{}, 30_000_000, 0, 100)
	require.NoError(t, err)
	require.Len(t, proposerConfig.EPBSBuilderConfig.Builders, 1)
	require.Nil(t, proposerConfig.EPBSBuilderConfig.Builders[0])
}

func TestExecutionConfigResolvesRootEPBSPolicy(t *testing.T) {
	minBid := phase0.Gwei(10)
	boost := uint64(120)
	builders := []*v2.EPBSBuilder{{URL: "https://builder.example", AuthData: []byte{0x12}}}
	config := &v2.ExecutionConfig{EPBSBuilderConfig: &v2.EPBSBuilderConfig{
		MinBid:             &minBid,
		BuilderBoostFactor: &boost,
		Builders:           &builders,
	}}

	proposerConfig, err := config.ProposerConfig(context.Background(), nil, phase0.BLSPubKey{}, bellatrix.ExecutionAddress{}, 30_000_000, 0, 100)
	require.NoError(t, err)
	require.Equal(t, minBid, proposerConfig.EPBSBuilderConfig.MinBid)
	require.Equal(t, boost, proposerConfig.EPBSBuilderConfig.BuilderBoostFactor)
	require.Equal(t, "https://builder.example", proposerConfig.EPBSBuilderConfig.Builders[0].URL)
	require.Equal(t, []byte{0x12}, proposerConfig.EPBSBuilderConfig.Builders[0].AuthData)
}

func TestExecutionConfigResolvesEPBSOverrides(t *testing.T) {
	pubkey := phase0.BLSPubKey{0x01}
	pubkeyString := fmt.Sprintf("%#x", pubkey)
	directBuilder := `{"url":"https://root-builder.example","auth_data":"0x12","builder_pubkeys":[],"max_execution_payment":"0","min_bid":"1","builder_boost_factor":100}`
	replacementBuilder := `{"url":"https://proposer-builder.example","auth_data":"0x34","builder_pubkeys":[],"max_execution_payment":"0","min_bid":"2","builder_boost_factor":110}`

	tests := []struct {
		name             string
		input            string
		expectedMinBid   phase0.Gwei
		expectedBoost    uint64
		expectedBuilders []string
	}{
		{
			name:           "ScalarInheritanceAndOmittedList",
			input:          fmt.Sprintf(`{"version":2,"epbs_builder_config":{"min_bid":"10","builder_boost_factor":120,"builders":[%s]},"proposers":[{"proposer":%q,"epbs_builder_config":{"builder_boost_factor":80}}]}`, directBuilder, pubkeyString),
			expectedMinBid: 10, expectedBoost: 80, expectedBuilders: []string{"https://root-builder.example"},
		},
		{
			name:           "ExplicitEmptyListDisables",
			input:          fmt.Sprintf(`{"version":2,"epbs_builder_config":{"builders":[%s]},"proposers":[{"proposer":%q,"epbs_builder_config":{"builders":[]}}]}`, directBuilder, pubkeyString),
			expectedMinBid: 0, expectedBoost: 100, expectedBuilders: []string{},
		},
		{
			name:           "ProposerListReplacesRoot",
			input:          fmt.Sprintf(`{"version":2,"epbs_builder_config":{"builders":[%s]},"proposers":[{"proposer":%q,"epbs_builder_config":{"builders":[%s]}}]}`, directBuilder, pubkeyString, replacementBuilder),
			expectedMinBid: 0, expectedBoost: 100, expectedBuilders: []string{"https://proposer-builder.example"},
		},
		{
			name:           "FirstMatchingProposerWins",
			input:          fmt.Sprintf(`{"version":2,"proposers":[{"proposer":%q,"epbs_builder_config":{"min_bid":"7"}},{"proposer":%q,"epbs_builder_config":{"min_bid":"9"}}]}`, pubkeyString, pubkeyString),
			expectedMinBid: 7, expectedBoost: 100, expectedBuilders: []string{},
		},
		{
			name:           "RelayMinimumDoesNotBecomeEPBSPolicy",
			input:          fmt.Sprintf(`{"version":2,"relays":{"https://relay.example":{"min_value":"99"}},"proposers":[{"proposer":%q,"relays":{"https://relay.example":{"min_value":"100"}}}]}`, pubkeyString),
			expectedMinBid: 0, expectedBoost: 100, expectedBuilders: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var config v2.ExecutionConfig
			require.NoError(t, json.Unmarshal([]byte(test.input), &config))
			resolved, err := config.ProposerConfig(context.Background(), nil, pubkey, bellatrix.ExecutionAddress{}, 30_000_000, 0, 100)
			require.NoError(t, err)
			require.Equal(t, test.expectedMinBid, resolved.EPBSBuilderConfig.MinBid)
			require.Equal(t, test.expectedBoost, resolved.EPBSBuilderConfig.BuilderBoostFactor)
			builderURLs := make([]string, len(resolved.EPBSBuilderConfig.Builders))
			for i := range resolved.EPBSBuilderConfig.Builders {
				builderURLs[i] = resolved.EPBSBuilderConfig.Builders[i].URL
			}
			require.Equal(t, test.expectedBuilders, builderURLs)
		})
	}
}

func TestExecutionConfigRejectsNilProposerDuringResolution(t *testing.T) {
	config := &v2.ExecutionConfig{Proposers: []*v2.ProposerConfig{nil}}

	resolved, err := config.ProposerConfig(context.Background(), nil, phase0.BLSPubKey{}, bellatrix.ExecutionAddress{}, 30_000_000, 0, 100)
	require.Nil(t, resolved)
	require.EqualError(t, err, "proposer config 0 is null")
}

func TestExecutionConfigExposesResolvedGasLimit(t *testing.T) {
	ctx := context.Background()
	gasLimit := uint64(30000000)
	config := &v2.ExecutionConfig{GasLimit: &gasLimit}

	proposerConfig, err := config.ProposerConfig(ctx,
		nil,
		phase0.BLSPubKey{},
		bellatrix.ExecutionAddress{},
		10000000,
		0,
		100,
	)

	require.NoError(t, err)
	require.Equal(t, gasLimit, proposerConfig.GasLimit)
}

func TestConfig(t *testing.T) {
	ctx := context.Background()

	require.NoError(t, e2types.InitBLS())
	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := hd.CreateWallet(ctx, "test wallet", []byte("pass"), store, encryptor, make([]byte, 64))
	require.NoError(t, err)
	require.Nil(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, []byte("pass")))
	account1, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(context.Background(), "test account 1", []byte("pass"))
	require.NoError(t, err)

	feeRecipient1 := bellatrix.ExecutionAddress{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	feeRecipient2 := bellatrix.ExecutionAddress{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02}
	feeRecipient3 := bellatrix.ExecutionAddress{0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03}
	feeRecipient4 := bellatrix.ExecutionAddress{0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04}

	gasLimit0 := uint64(0)
	gasLimit1 := uint64(1000000)
	gasLimit2 := uint64(2000000)
	gasLimit3 := uint64(3000000)
	gasLimit4 := uint64(4000000)

	grace0 := 0 * time.Second
	grace1 := time.Second
	grace2 := 2 * time.Second

	minValue0 := decimal.Zero
	minValue1 := decimal.New(1, 0)
	minValue2 := decimal.New(2, 0)

	pubkey1 := phase0.BLSPubKey{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	pubkey2 := phase0.BLSPubKey{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02}

	tests := []struct {
		name                 string
		executionConfig      *v2.ExecutionConfig
		account              e2wtypes.Account
		pubkey               phase0.BLSPubKey
		fallbackFeeRecipient bellatrix.ExecutionAddress
		fallbackGasLimit     uint64
		expected             *beaconblockproposer.ProposerConfig
		err                  string
	}{
		{
			name:                 "FallbacksWithoutRelays",
			executionConfig:      &v2.ExecutionConfig{},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient1,
				GasLimit:          gasLimit1,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays:            []*beaconblockproposer.RelayConfig{},
			},
		},
		{
			name: "FallbacksWithRelays",
			executionConfig: &v2.ExecutionConfig{
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient1,
				GasLimit:          gasLimit1,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: feeRecipient1,
						GasLimit:     gasLimit1,
						Grace:        0,
						MinValue:     decimal.Zero,
					},
				},
			},
		},
		{
			name: "BaseNoRelays",
			executionConfig: &v2.ExecutionConfig{
				Version:      2,
				FeeRecipient: &feeRecipient2,
				GasLimit:     &gasLimit2,
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     uint64(12345),
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient2,
				GasLimit:          gasLimit2,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays:            []*beaconblockproposer.RelayConfig{},
			},
		},
		{
			name: "Base",
			executionConfig: &v2.ExecutionConfig{
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {
						FeeRecipient: &feeRecipient2,
						GasLimit:     &gasLimit2,
						Grace:        &grace1,
						MinValue:     &minValue1,
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient1,
				GasLimit:          gasLimit1,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: feeRecipient2,
						GasLimit:     gasLimit2,
						Grace:        grace1,
						MinValue:     minValue1,
					},
				},
			},
		},
		{
			name: "ProposerAccountMatch",
			executionConfig: &v2.ExecutionConfig{
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {
						FeeRecipient: &feeRecipient2,
						GasLimit:     &gasLimit2,
						Grace:        &grace1,
						MinValue:     &minValue1,
					},
				},
				Proposers: []*v2.ProposerConfig{
					{
						Account:      regexp.MustCompile("^test.*/test.*$"),
						FeeRecipient: &feeRecipient3,
						GasLimit:     &gasLimit3,
						Grace:        &grace2,
						MinValue:     &minValue2,
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient3,
				GasLimit:          gasLimit3,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: feeRecipient3,
						GasLimit:     gasLimit3,
						Grace:        grace2,
						MinValue:     minValue2,
					},
				},
			},
		},
		{
			name: "ProposerAccountNoMatch",
			executionConfig: &v2.ExecutionConfig{
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {
						FeeRecipient: &feeRecipient2,
						GasLimit:     &gasLimit2,
						Grace:        &grace1,
						MinValue:     &minValue1,
					},
				},
				Proposers: []*v2.ProposerConfig{
					{
						Account:      regexp.MustCompile("^fail to match.*/test.*$"),
						FeeRecipient: &feeRecipient3,
						GasLimit:     &gasLimit3,
						Grace:        &grace2,
						MinValue:     &minValue2,
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient1,
				GasLimit:          gasLimit1,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: feeRecipient2,
						GasLimit:     gasLimit2,
						Grace:        grace1,
						MinValue:     minValue1,
					},
				},
			},
		},
		{
			name: "ProposerAccountMatchRelay",
			executionConfig: &v2.ExecutionConfig{
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {
						FeeRecipient: &feeRecipient2,
						GasLimit:     &gasLimit2,
						Grace:        &grace1,
						MinValue:     &minValue1,
					},
				},
				Proposers: []*v2.ProposerConfig{
					{
						Account: regexp.MustCompile("^test.*/test.*$"),
						Relays: map[string]*v2.ProposerRelayConfig{
							"https://relay1.com/": {
								FeeRecipient: &feeRecipient3,
								GasLimit:     &gasLimit3,
								Grace:        &grace2,
								MinValue:     &minValue2,
							},
						},
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient1,
				GasLimit:          gasLimit1,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: feeRecipient3,
						GasLimit:     gasLimit3,
						Grace:        grace2,
						MinValue:     minValue2,
					},
				},
			},
		},
		{
			name: "ProposerValidatorMatch",
			executionConfig: &v2.ExecutionConfig{
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {
						FeeRecipient: &feeRecipient2,
						GasLimit:     &gasLimit2,
						Grace:        &grace1,
						MinValue:     &minValue1,
					},
				},
				Proposers: []*v2.ProposerConfig{
					{
						Validator:    pubkey1,
						FeeRecipient: &feeRecipient3,
						GasLimit:     &gasLimit3,
						Grace:        &grace2,
						MinValue:     &minValue2,
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient3,
				GasLimit:          gasLimit3,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: feeRecipient3,
						GasLimit:     gasLimit3,
						Grace:        grace2,
						MinValue:     minValue2,
					},
				},
			},
		},
		{
			name: "ProposerValidatorNoMatch",
			executionConfig: &v2.ExecutionConfig{
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {
						FeeRecipient: &feeRecipient2,
						GasLimit:     &gasLimit2,
						Grace:        &grace1,
						MinValue:     &minValue1,
					},
				},
				Proposers: []*v2.ProposerConfig{
					{
						Validator:    pubkey2,
						FeeRecipient: &feeRecipient3,
						GasLimit:     &gasLimit3,
						Grace:        &grace2,
						MinValue:     &minValue2,
					},
				},
			},
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient1,
				GasLimit:          gasLimit1,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: feeRecipient2,
						GasLimit:     gasLimit2,
						Grace:        grace1,
						MinValue:     minValue1,
					},
				},
			},
		},
		{
			name: "ProposerValidatorRelayMatch",
			executionConfig: &v2.ExecutionConfig{
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {
						FeeRecipient: &feeRecipient2,
						GasLimit:     &gasLimit2,
						Grace:        &grace1,
						MinValue:     &minValue1,
					},
				},
				Proposers: []*v2.ProposerConfig{
					{
						Validator:    pubkey1,
						FeeRecipient: &feeRecipient3,
						GasLimit:     &gasLimit3,
						Grace:        &grace2,
						MinValue:     &minValue2,
						Relays: map[string]*v2.ProposerRelayConfig{
							"https://relay1.com/": {
								FeeRecipient: &feeRecipient4,
								GasLimit:     &gasLimit4,
								Grace:        &grace2,
								MinValue:     &minValue2,
							},
						},
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient3,
				GasLimit:          gasLimit3,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: feeRecipient4,
						GasLimit:     gasLimit4,
						Grace:        grace2,
						MinValue:     minValue2,
					},
				},
			},
		},
		{
			name: "ProposerValidatorResetRelays",
			executionConfig: &v2.ExecutionConfig{
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {
						FeeRecipient: &feeRecipient2,
						GasLimit:     &gasLimit2,
						Grace:        &grace1,
						MinValue:     &minValue1,
					},
				},
				Proposers: []*v2.ProposerConfig{
					{
						Validator:    pubkey1,
						FeeRecipient: &feeRecipient3,
						GasLimit:     &gasLimit3,
						Grace:        &grace2,
						MinValue:     &minValue2,
						ResetRelays:  true,
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient3,
				GasLimit:          gasLimit3,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays:            []*beaconblockproposer.RelayConfig{},
			},
		},
		{
			name: "ProposerValidatorResetRelaysAndAdd",
			executionConfig: &v2.ExecutionConfig{
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {
						FeeRecipient: &feeRecipient2,
						GasLimit:     &gasLimit2,
						Grace:        &grace1,
						MinValue:     &minValue1,
					},
				},
				Proposers: []*v2.ProposerConfig{
					{
						Validator:    pubkey1,
						FeeRecipient: &feeRecipient3,
						GasLimit:     &gasLimit3,
						Grace:        &grace2,
						MinValue:     &minValue2,
						ResetRelays:  true,
						Relays: map[string]*v2.ProposerRelayConfig{
							"https://relay3.com/": {},
						},
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient3,
				GasLimit:          gasLimit3,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay3.com/",
						FeeRecipient: feeRecipient3,
						GasLimit:     gasLimit3,
						Grace:        grace2,
						MinValue:     minValue2,
					},
				},
			},
		},
		{
			name: "ProposerValidatorResetRelaysAndAddWithConfig",
			executionConfig: &v2.ExecutionConfig{
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {
						FeeRecipient: &feeRecipient2,
						GasLimit:     &gasLimit2,
						Grace:        &grace1,
						MinValue:     &minValue1,
					},
				},
				Proposers: []*v2.ProposerConfig{
					{
						Validator:    pubkey1,
						FeeRecipient: &feeRecipient3,
						GasLimit:     &gasLimit3,
						Grace:        &grace2,
						MinValue:     &minValue2,
						ResetRelays:  true,
						Relays: map[string]*v2.ProposerRelayConfig{
							"https://relay3.com/": {
								FeeRecipient: &feeRecipient4,
								GasLimit:     &gasLimit4,
								Grace:        &grace2,
								MinValue:     &minValue2,
							},
						},
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient3,
				GasLimit:          gasLimit3,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay3.com/",
						FeeRecipient: feeRecipient4,
						GasLimit:     gasLimit4,
						Grace:        grace2,
						MinValue:     minValue2,
					},
				},
			},
		},
		{
			name: "ProposerValidatorRelayExplicitZeros",
			executionConfig: &v2.ExecutionConfig{
				Proposers: []*v2.ProposerConfig{
					{
						Validator:    pubkey1,
						FeeRecipient: &feeRecipient3,
						GasLimit:     &gasLimit3,
						Grace:        &grace2,
						MinValue:     &minValue2,
						ResetRelays:  true,
						Relays: map[string]*v2.ProposerRelayConfig{
							"https://relay1.com/": {
								FeeRecipient: &feeRecipient4,
								GasLimit:     &gasLimit0,
								Grace:        &grace0,
								MinValue:     &minValue0,
							},
						},
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient3,
				GasLimit:          gasLimit3,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: feeRecipient4,
						GasLimit:     gasLimit0,
						Grace:        grace0,
						MinValue:     minValue0,
					},
				},
			},
		},
		{
			name: "ProposerValidatorRelayFromExecutionConfig",
			executionConfig: &v2.ExecutionConfig{
				FeeRecipient: &feeRecipient2,
				GasLimit:     &gasLimit2,
				Grace:        &grace1,
				MinValue:     &minValue1,
				Proposers: []*v2.ProposerConfig{
					{
						Validator: pubkey1,
						Relays: map[string]*v2.ProposerRelayConfig{
							"https://relay3.com/": {},
						},
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient2,
				GasLimit:          gasLimit2,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay3.com/",
						FeeRecipient: feeRecipient2,
						GasLimit:     gasLimit2,
						Grace:        grace1,
						MinValue:     minValue1,
					},
				},
			},
		},
		{
			name: "ProposerValidatorRelayFromFallback",
			executionConfig: &v2.ExecutionConfig{
				Proposers: []*v2.ProposerConfig{
					{
						Validator: pubkey1,
						Relays: map[string]*v2.ProposerRelayConfig{
							"https://relay3.com/": {},
						},
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient1,
				GasLimit:          gasLimit1,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay3.com/",
						FeeRecipient: feeRecipient1,
						GasLimit:     gasLimit1,
						Grace:        grace0,
						MinValue:     minValue0,
					},
				},
			},
		},
		{
			name: "ExecutionConfigDefaultGasLimit",
			executionConfig: &v2.ExecutionConfig{
				GasLimit:     &gasLimit4,
				Proposers:    []*v2.ProposerConfig{},
				FeeRecipient: &feeRecipient3,
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient3,
				GasLimit:          gasLimit4,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: feeRecipient3,
						GasLimit:     gasLimit4,
						Grace:        grace0,
						MinValue:     minValue0,
					},
				},
			},
		},
		{
			name: "ExecutionConfigDefaultAndRelayGasLimit",
			executionConfig: &v2.ExecutionConfig{
				GasLimit:     &gasLimit4,
				Proposers:    []*v2.ProposerConfig{},
				FeeRecipient: &feeRecipient3,
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {
						GasLimit: &gasLimit3,
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			expected: &beaconblockproposer.ProposerConfig{
				FeeRecipient:      feeRecipient3,
				GasLimit:          gasLimit4,
				EPBSBuilderConfig: defaultEPBSBuilderConfig(),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: feeRecipient3,
						GasLimit:     gasLimit3,
						Grace:        grace0,
						MinValue:     minValue0,
					},
				},
			},
		},
		{
			name: "InvalidProposerConfig",
			executionConfig: &v2.ExecutionConfig{
				Relays: map[string]*v2.BaseRelayConfig{
					"https://relay1.com/": {
						FeeRecipient: &feeRecipient2,
						GasLimit:     &gasLimit2,
						Grace:        &grace1,
						MinValue:     &minValue1,
					},
				},
				Proposers: []*v2.ProposerConfig{
					{
						FeeRecipient: &feeRecipient3,
						GasLimit:     &gasLimit3,
						Grace:        &grace2,
						MinValue:     &minValue2,
					},
				},
			},
			account:              account1,
			pubkey:               pubkey1,
			fallbackFeeRecipient: feeRecipient1,
			fallbackGasLimit:     gasLimit1,
			err:                  "proposer config without either account or validator; cannot apply",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := test.executionConfig.ProposerConfig(ctx, test.account, test.pubkey, test.fallbackFeeRecipient, test.fallbackGasLimit, 0, 100)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expected, res)
			}
		})
	}
}

// defaultEPBSBuilderConfig is the ePBS policy resolved when the configuration sets no ePBS values.
func defaultEPBSBuilderConfig() *beaconblockproposer.EPBSBuilderConfig {
	return &beaconblockproposer.EPBSBuilderConfig{
		MinBid:             0,
		BuilderBoostFactor: 100,
		Builders:           []*beaconblockproposer.EPBSBuilder{},
	}
}

func TestExecutionConfigEPBSPrecedence(t *testing.T) {
	pubkey := phase0.BLSPubKey{0x01}
	pubkeyString := fmt.Sprintf("%#x", pubkey)

	tests := []struct {
		name           string
		input          string
		expectedMinBid phase0.Gwei
		expectedBoost  uint64
	}{
		{
			name:           "Fallbacks",
			input:          `{"version":2}`,
			expectedMinBid: 7, expectedBoost: 0,
		},
		{
			name:           "RootOverridesFallbacks",
			input:          `{"version":2,"epbs_builder_config":{"min_bid":"11","builder_boost_factor":120}}`,
			expectedMinBid: 11, expectedBoost: 120,
		},
		{
			name:           "ProposerOverridesRoot",
			input:          fmt.Sprintf(`{"version":2,"epbs_builder_config":{"min_bid":"11","builder_boost_factor":120},"proposers":[{"proposer":%q,"epbs_builder_config":{"min_bid":"13","builder_boost_factor":140}}]}`, pubkeyString),
			expectedMinBid: 13, expectedBoost: 140,
		},
		{
			name:           "ProposerOverridesFallbacks",
			input:          fmt.Sprintf(`{"version":2,"proposers":[{"proposer":%q,"epbs_builder_config":{"min_bid":"13","builder_boost_factor":140}}]}`, pubkeyString),
			expectedMinBid: 13, expectedBoost: 140,
		},
		{
			name:           "RootMinValueIgnored",
			input:          `{"version":2,"min_value":"0.0000000012"}`,
			expectedMinBid: 7, expectedBoost: 0,
		},
		{
			name:           "ProposerMinValueIgnored",
			input:          fmt.Sprintf(`{"version":2,"epbs_builder_config":{"min_bid":"11"},"min_value":"1","proposers":[{"proposer":%q,"min_value":"0.0000000021"}]}`, pubkeyString),
			expectedMinBid: 11, expectedBoost: 0,
		},
		{
			name:           "MinValueAboveGweiLimitIgnored",
			input:          `{"version":2,"min_value":"18446744073.709551616"}`,
			expectedMinBid: 7, expectedBoost: 0,
		},
		{
			name:           "FieldsResolveIndependently",
			input:          fmt.Sprintf(`{"version":2,"epbs_builder_config":{"builder_boost_factor":120},"proposers":[{"proposer":%q,"epbs_builder_config":{"min_bid":"13"}}]}`, pubkeyString),
			expectedMinBid: 13, expectedBoost: 120,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var config v2.ExecutionConfig
			require.NoError(t, json.Unmarshal([]byte(test.input), &config))
			resolved, err := config.ProposerConfig(context.Background(), nil, pubkey, bellatrix.ExecutionAddress{}, 30_000_000, 7, 0)
			require.NoError(t, err)
			require.Equal(t, test.expectedMinBid, resolved.EPBSBuilderConfig.MinBid)
			require.Equal(t, test.expectedBoost, resolved.EPBSBuilderConfig.BuilderBoostFactor)
		})
	}
}

func TestExecutionConfigHasMinValueWithoutEPBSMinBid(t *testing.T) {
	pubkeyString := fmt.Sprintf("%#x", phase0.BLSPubKey{0x01})

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:  "NoMinValue",
			input: `{"version":2}`,
		},
		{
			name:     "RootMinValue",
			input:    `{"version":2,"min_value":"0.1"}`,
			expected: true,
		},
		{
			name:  "RootMinValueWithRootMinBid",
			input: `{"version":2,"min_value":"0.1","epbs_builder_config":{"min_bid":"0"}}`,
		},
		{
			name:     "ProposerMinValue",
			input:    fmt.Sprintf(`{"version":2,"proposers":[{"proposer":%q,"min_value":"0.1"}]}`, pubkeyString),
			expected: true,
		},
		{
			name:     "ProposerMinValueWithRootMinBid",
			input:    fmt.Sprintf(`{"version":2,"epbs_builder_config":{"min_bid":"0"},"proposers":[{"proposer":%q,"min_value":"0.1"}]}`, pubkeyString),
			expected: true,
		},
		{
			name:  "ProposerMinValueWithProposerMinBid",
			input: fmt.Sprintf(`{"version":2,"proposers":[{"proposer":%q,"min_value":"0.1","epbs_builder_config":{"min_bid":"0"}}]}`, pubkeyString),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var config v2.ExecutionConfig
			require.NoError(t, json.Unmarshal([]byte(test.input), &config))
			require.Equal(t, test.expected, config.HasMinValueWithoutEPBSMinBid())
		})
	}
}

func TestExecutionConfigEPBSEntryInheritance(t *testing.T) {
	pubkey := phase0.BLSPubKey{0x01}
	pubkeyString := fmt.Sprintf("%#x", pubkey)
	bareBuilder := `{"url":"https://bare-builder.example","auth_data":"0x12","builder_pubkeys":[],"max_execution_payment":"0"}`
	explicitBuilder := `{"url":"https://explicit-builder.example","auth_data":"0x34","builder_pubkeys":[],"max_execution_payment":"0","min_bid":"3","builder_boost_factor":0}`

	tests := []struct {
		name           string
		input          string
		expectedMinBid []phase0.Gwei
		expectedBoost  []uint64
	}{
		{
			name:           "RootEntriesInheritFallbacks",
			input:          fmt.Sprintf(`{"version":2,"epbs_builder_config":{"builders":[%s,%s]}}`, bareBuilder, explicitBuilder),
			expectedMinBid: []phase0.Gwei{7, 3}, expectedBoost: []uint64{90, 0},
		},
		{
			name:           "RootEntriesInheritRoot",
			input:          fmt.Sprintf(`{"version":2,"epbs_builder_config":{"min_bid":"11","builder_boost_factor":120,"builders":[%s,%s]}}`, bareBuilder, explicitBuilder),
			expectedMinBid: []phase0.Gwei{11, 3}, expectedBoost: []uint64{120, 0},
		},
		{
			name:           "RootEntriesInheritProposer",
			input:          fmt.Sprintf(`{"version":2,"epbs_builder_config":{"min_bid":"11","builder_boost_factor":120,"builders":[%s,%s]},"proposers":[{"proposer":%q,"epbs_builder_config":{"builder_boost_factor":140}}]}`, bareBuilder, explicitBuilder, pubkeyString),
			expectedMinBid: []phase0.Gwei{11, 3}, expectedBoost: []uint64{140, 0},
		},
		{
			name:           "ProposerEntriesInheritProposer",
			input:          fmt.Sprintf(`{"version":2,"proposers":[{"proposer":%q,"epbs_builder_config":{"min_bid":"13","builders":[%s,%s]}}]}`, pubkeyString, bareBuilder, explicitBuilder),
			expectedMinBid: []phase0.Gwei{13, 3}, expectedBoost: []uint64{90, 0},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var config v2.ExecutionConfig
			require.NoError(t, json.Unmarshal([]byte(test.input), &config))
			resolved, err := config.ProposerConfig(context.Background(), nil, pubkey, bellatrix.ExecutionAddress{}, 30_000_000, 7, 90)
			require.NoError(t, err)
			minBids := make([]phase0.Gwei, len(resolved.EPBSBuilderConfig.Builders))
			boosts := make([]uint64, len(resolved.EPBSBuilderConfig.Builders))
			for i, builder := range resolved.EPBSBuilderConfig.Builders {
				minBids[i] = builder.MinBid
				boosts[i] = builder.BuilderBoostFactor
			}
			require.Equal(t, test.expectedMinBid, minBids)
			require.Equal(t, test.expectedBoost, boosts)
		})
	}
}
