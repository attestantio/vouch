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

package v2_test

import (
	"encoding/json"
	"testing"

	v2 "github.com/attestantio/vouch/services/blockrelay/v2"
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
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type v2.proposerConfigJSON",
		},
		{
			name:  "ProposerMissing",
			input: []byte(`{"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "proposer is missing",
		},
		{
			name:  "ProposerWrongType",
			input: []byte(`{"proposer":true,"fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field proposerConfigJSON.proposer of type string",
		},
		{
			name:  "ProposerPubkeyInvalid",
			input: []byte(`{"proposer":"0xinvalid","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "failed to decode proposer 0xinvalid: encoding/hex: invalid byte: U+0069 'i'",
		},
		{
			name:  "ProposerPubkeyWrongLength",
			input: []byte(`{"proposer":"0x222222222222222222222222222222222222222222222222","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "incorrect length for proposer 0x222222222222222222222222222222222222222222222222",
		},
		{
			name:  "ProposerInvalidRegex",
			input: []byte(`{"proposer":"*","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "invalid account proposer *: error parsing regexp: missing argument to repetition operator: `*`",
		},
		{
			name:  "FeeRecipientWrongType",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":true,"gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field proposerConfigJSON.fee_recipient of type string",
		},
		{
			name:  "FeeRecipientInvalid",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":"true","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "failed to decode fee recipient: encoding/hex: invalid byte: U+0074 't'",
		},
		{
			name:  "FeeRecipientIncorrectLength",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":"0x11111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
			err:   "incorrect length for fee recipient",
		},
		{
			name:  "GasLimitWrongType",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":true,"grace":"1000","min_value":"0.5"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field proposerConfigJSON.gas_limit of type string",
		},
		{
			name:  "GasLimitInvalid",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"true","grace":"1000","min_value":"0.5"}`),
			err:   "invalid gas limit: strconv.ParseUint: parsing \"true\": invalid syntax",
		},
		{
			name:  "GasLimitNegative",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"-1","grace":"1000","min_value":"0.5"}`),
			err:   "invalid gas limit: strconv.ParseUint: parsing \"-1\": invalid syntax",
		},
		{
			name:  "GraceWrongType",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":true,"min_value":"0.5"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field proposerConfigJSON.grace of type string",
		},
		{
			name:  "GraceInvalid",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"true","min_value":"0.5"}`),
			err:   "grace invalid: strconv.ParseUint: parsing \"true\": invalid syntax",
		},
		{
			name:  "GraceNegative",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"-1","min_value":"0.5"}`),
			err:   "grace invalid: strconv.ParseUint: parsing \"-1\": invalid syntax",
		},
		{
			name:  "MinValueWrongType",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":true}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field proposerConfigJSON.min_value of type string",
		},
		{
			name:  "MinValueInvalid",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"true"}`),
			err:   "min value invalid: can't convert true to decimal: exponent is not numeric",
		},
		{
			name:  "MinValueNegative",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"-1"}`),
			err:   "min value cannot be negative",
		},
		{
			name:  "Good",
			input: []byte(`{"proposer":"^Wallet/Account$","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
		},
		{
			name:  "GoodPubkey",
			input: []byte(`{"proposer":"0x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222","fee_recipient":"0x1111111111111111111111111111111111111111","gas_limit":"30000000","grace":"1000","min_value":"0.5"}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res v2.ProposerConfig
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
