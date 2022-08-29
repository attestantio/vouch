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

package blockrelay_test

import (
	"encoding/json"
	"testing"

	"github.com/attestantio/vouch/services/blockrelay"
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
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type blockrelay.executionConfigJSON",
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
			err:   "invalid JSON: invalid JSON: json: cannot unmarshal bool into Go value of type blockrelay.proposerConfigJSON",
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
			var res blockrelay.ExecutionConfig
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
