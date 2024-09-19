// Copyright © 2024 Attestant Limited.
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

package v1_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	v1 "github.com/attestantio/vouch/services/blockrelay/v1"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
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
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type v1.executionConfigJSON",
		},
		{
			name:  "ProposerConfigKeyWrongType",
			input: []byte(`{"proposer_config":{true:{"fee_recipient":"0x1111111111111111111111111111111111111111"},"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"fee_recipient":"0x2222222222222222222222222222222222222222"}},"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213"}}`),
			err:   "invalid character 't' looking for beginning of object key string",
		},
		{
			name:  "ProposerConfigKeyInvalid",
			input: []byte(`{"proposer_config":{"true":{"fee_recipient":"0x1111111111111111111111111111111111111111"},"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"fee_recipient":"0x2222222222222222222222222222222222222222"}},"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213"}}`),
			err:   "failed to decode public key: encoding/hex: invalid byte: U+0074 't'",
		},
		{
			name:  "ProposerConfigKeyIncorrectLength",
			input: []byte(`{"proposer_config":{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"fee_recipient":"0x1111111111111111111111111111111111111111"},"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"fee_recipient":"0x2222222222222222222222222222222222222222"}},"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213"}}`),
			err:   "public key has 47 bytes, should have 48",
		},
		{
			name:  "DefaultConfigMissing",
			input: []byte(`{"proposer_config":{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"fee_recipient":"0x1111111111111111111111111111111111111111"}}}`),
			err:   "default config missing",
		},
		{
			name:  "DefaultConfigWrongType",
			input: []byte(`{"proposer_config":{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"fee_recipient":"0x1111111111111111111111111111111111111111"}},"default_config":true}`),
			err:   "invalid JSON: invalid JSON: json: cannot unmarshal bool into Go value of type v1.proposerConfigJSON",
		},
		{
			name:  "Minimal",
			input: []byte(`{"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213"}}`),
		},
		{
			name:  "DefaultWithGasLimit",
			input: []byte(`{"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213","gas_limit":"1000000"}}`),
		},
		{
			name:  "ProposerConfig",
			input: []byte(`{"proposer_config":{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"fee_recipient":"0x1111111111111111111111111111111111111111"},"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"fee_recipient":"0x2222222222222222222222222222222222222222"}},"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213"}}`),
		},
		{
			name:  "DocExample1",
			input: []byte(`{"proposer_config":{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"fee_recipient":"0x1111111111111111111111111111111111111111"},"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"fee_recipient":"0x2222222222222222222222222222222222222222"}},"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213"}}`),
		},
		{
			name:  "DocExample2",
			input: []byte(`{"proposer_config":{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"fee_recipient":"0x1111111111111111111111111111111111111111","builder":{"enabled":true,"relays":["relay1.example.com","relay2.example.com"]}},"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"fee_recipient":"0x2222222222222222222222222222222222222222","builder":{"enabled":false}}},"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213","builder":{"enabled":true,"relays":["relay1.example.com","relay2.example.com"]}}}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res v1.ExecutionConfig
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

func executionAddress(input string) bellatrix.ExecutionAddress {
	data, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		panic(err)
	}
	if len(data) != bellatrix.ExecutionAddressLength {
		panic("execution address incorrect length")
	}
	var ex bellatrix.ExecutionAddress
	copy(ex[:], data)
	return ex
}

func pubkey(input string) phase0.BLSPubKey {
	data, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		panic(err)
	}
	if len(data) != phase0.PublicKeyLength {
		panic("bls public key incorrect length")
	}
	var pk phase0.BLSPubKey
	copy(pk[:], data)
	return pk
}

func TestECProposerConfig(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name                 string
		fallbackFeeRecipient bellatrix.ExecutionAddress
		fallbackGasLimit     uint64
		input                []byte
		pubkey               phase0.BLSPubKey
		pc                   *beaconblockproposer.ProposerConfig
		err                  string
	}{
		{
			name:                 "DefaultNoRelays",
			fallbackFeeRecipient: executionAddress("0x0101010101010101010101010101010101010101"),
			fallbackGasLimit:     12345,
			input:                []byte(`{"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213"}}`),
			pc: &beaconblockproposer.ProposerConfig{
				FeeRecipient: executionAddress("0x000102030405060708090a0b0c0d0e0f10111213"),
				Relays:       []*beaconblockproposer.RelayConfig{},
			},
		},
		{
			name:                 "Default",
			fallbackFeeRecipient: executionAddress("0x0101010101010101010101010101010101010101"),
			fallbackGasLimit:     12345,
			input:                []byte(`{"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213","builder":{"enabled":true,"relays": ["https://relay1.com/"]}}}`),
			pc: &beaconblockproposer.ProposerConfig{
				FeeRecipient: executionAddress("0x000102030405060708090a0b0c0d0e0f10111213"),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: executionAddress("0x000102030405060708090a0b0c0d0e0f10111213"),
						GasLimit:     12345,
						MinValue:     decimal.Zero,
					},
				},
			},
		},
		{
			name:                 "OverrideGasLimit",
			fallbackFeeRecipient: executionAddress("0x0101010101010101010101010101010101010101"),
			fallbackGasLimit:     12345,
			input:                []byte(`{"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213","gas_limit":"23456","builder":{"enabled":true,"relays": ["https://relay1.com/"]}}}`),
			pc: &beaconblockproposer.ProposerConfig{
				FeeRecipient: executionAddress("0x000102030405060708090a0b0c0d0e0f10111213"),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: executionAddress("0x000102030405060708090a0b0c0d0e0f10111213"),
						GasLimit:     23456,
						MinValue:     decimal.Zero,
					},
				},
			},
		},
		{
			name:                 "NilProposerConfig",
			fallbackFeeRecipient: executionAddress("0x0101010101010101010101010101010101010101"),
			fallbackGasLimit:     12345,
			input:                []byte(`{"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213","gas_limit":"23456","builder":{"enabled":true,"relays": ["https://relay1.com/"]}},"proposer_configs":{"0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111": null}}`),
			pubkey:               pubkey("0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"),
			pc: &beaconblockproposer.ProposerConfig{
				FeeRecipient: executionAddress("0x000102030405060708090a0b0c0d0e0f10111213"),
				Relays: []*beaconblockproposer.RelayConfig{
					{
						Address:      "https://relay1.com/",
						FeeRecipient: executionAddress("0x000102030405060708090a0b0c0d0e0f10111213"),
						GasLimit:     23456,
						MinValue:     decimal.Zero,
					},
				},
			},
		},
		{
			name:                 "ProposerConfig",
			fallbackFeeRecipient: executionAddress("0x0101010101010101010101010101010101010101"),
			fallbackGasLimit:     12345,
			input:                []byte(`{"default_config":{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213","gas_limit":"23456","builder":{"enabled":true,"relays": ["https://relay1.com/"]}},"proposer_config":{"0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111": {"fee_recipient":"0x0102030405060708090a0b0c0d0e0f1011121314","gas_limit":"34567"}}}`),
			pubkey:               pubkey("0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"),
			pc: &beaconblockproposer.ProposerConfig{
				FeeRecipient: executionAddress("0x0102030405060708090a0b0c0d0e0f1011121314"),
				Relays:       []*beaconblockproposer.RelayConfig{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var ec v1.ExecutionConfig
			err := json.Unmarshal(test.input, &ec)
			require.NoError(t, err)

			pc, err := ec.ProposerConfig(ctx, nil, test.pubkey, test.fallbackFeeRecipient, test.fallbackGasLimit)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.pc, pc)
			}
		})
	}
}
