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
	"encoding/json"
	"testing"

	v1 "github.com/attestantio/vouch/services/blockrelay/v1"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestProposerConfig(t *testing.T) {
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
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type v1.proposerConfigJSON",
		},
		{
			name:  "FeeRecpientMissing",
			input: []byte(`{"gas_limit":"1000000","builder":{"enabled":false}}`),
			err:   "fee recipient missing",
		},
		{
			name:  "FeeRecpientWrongType",
			input: []byte(`{"fee_recipient":true,"gas_limit":"1000000","builder":{"enabled":false}}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field proposerConfigJSON.fee_recipient of type string",
		},
		{
			name:  "FeeRecpientInvalid",
			input: []byte(`{"fee_recipient":"true","gas_limit":"1000000","builder":{"enabled":false}}`),
			err:   "failed to decode fee recipient: encoding/hex: invalid byte: U+0074 't'",
		},
		{
			name:  "GasLimitWrongType",
			input: []byte(`{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213","gas_limit":true,"builder":{"enabled":false}}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field proposerConfigJSON.gas_limit of type string",
		},
		{
			name:  "GasLimitInvalid",
			input: []byte(`{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213","gas_limit":"true","builder":{"enabled":false}}`),
			err:   "invalid gas limit: strconv.ParseUint: parsing \"true\": invalid syntax",
		},
		{
			name:  "BuilderWrongType",
			input: []byte(`{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213","gas_limit":"1000000","builder":true}`),
			err:   "invalid JSON: invalid JSON: json: cannot unmarshal bool into Go value of type v1.builderConfigJSON",
		},
		{
			name:  "Good",
			input: []byte(`{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213","gas_limit":"1000000","builder":{"enabled":false}}`),
		},
		{
			name:  "GoodGasLimitMisisng",
			input: []byte(`{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213","builder":{"enabled":false}}`),
		},
		{
			name:  "GoodBuilderMissing",
			input: []byte(`{"fee_recipient":"0x000102030405060708090a0b0c0d0e0f10111213","gas_limit":"1000000"}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res v1.ProposerConfig
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
