// Copyright © 2026 Attestant Limited.
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
	"fmt"
	"math"
	"strings"
	"testing"

	v2 "github.com/attestantio/vouch/services/blockrelay/v2"
	"github.com/stretchr/testify/require"
)

func TestEPBSBuilderConfigValidation(t *testing.T) {
	validPubkey := "0x" + strings.Repeat("11", 48)
	validBuilder := func(overrides string) string {
		return fmt.Sprintf(`{"url":"https://builder.example","auth_data":"0xdeadbeef","builder_pubkeys":[%q],"max_execution_payment":"0","min_bid":"1","builder_boost_factor":100%s}`, validPubkey, overrides)
	}
	config := func(builder string) []byte {
		return fmt.Appendf(nil, `{"version":2,"epbs_builder_config":{"builders":[%s]}}`, builder)
	}

	tests := []struct {
		name  string
		input []byte
		err   string
	}{
		{name: "URLMissing", input: config(validBuilder(`,"url":""`)), err: "direct builder URL is missing"},
		{name: "URLInvalidScheme", input: config(validBuilder(`,"url":"ftp://builder.example"`)), err: "direct builder URL is invalid"},
		{name: "URLWithoutHost", input: config(validBuilder(`,"url":"https:///bid"`)), err: "direct builder URL is invalid"},
		{name: "URLTooLong", input: config(validBuilder(fmt.Sprintf(`,"url":"https://%s.example"`, strings.Repeat("a", 2041)))), err: "direct builder URL exceeds 2048 bytes"},
		{name: "AuthMissing", input: config(validBuilder(`,"auth_data":""`)), err: "direct builder authorization data is missing"},
		{name: "AuthWithoutPrefix", input: config(validBuilder(`,"auth_data":"deadbeef"`)), err: "direct builder authorization data is missing 0x prefix"},
		{name: "AuthInvalidHex", input: config(validBuilder(`,"auth_data":"0xsecret"`)), err: "direct builder authorization data is invalid hex"},
		{name: "AuthEmpty", input: config(validBuilder(`,"auth_data":"0x"`)), err: "direct builder authorization data is empty"},
		{name: "AuthTooLong", input: config(validBuilder(fmt.Sprintf(`,"auth_data":"0x%s"`, strings.Repeat("11", 4097)))), err: "direct builder authorization data exceeds 4096 bytes"},
		{name: "PubkeysMissing", input: config(validBuilder(`,"builder_pubkeys":null`)), err: "direct builder public key allowlist is missing"},
		{name: "PubkeyWithoutPrefix", input: config(validBuilder(`,"builder_pubkeys":["11"]`)), err: "direct builder public key 0 is missing 0x prefix"},
		{name: "PubkeyInvalidHex", input: config(validBuilder(`,"builder_pubkeys":["0xzz"]`)), err: "direct builder public key 0 is invalid hex"},
		{name: "PubkeyWrongLength", input: config(validBuilder(`,"builder_pubkeys":["0x11"]`)), err: "direct builder public key 0 has incorrect length"},
		{name: "PaymentMissing", input: config(validBuilder(`,"max_execution_payment":""`)), err: "direct builder max execution payment is missing"},
		{name: "PaymentInvalid", input: config(validBuilder(`,"max_execution_payment":"-1"`)), err: "direct builder max execution payment is invalid"},
		{name: "MinimumMissing", input: config(validBuilder(`,"min_bid":""`)), err: "direct builder minimum bid is missing"},
		{name: "MinimumInvalid", input: config(validBuilder(`,"min_bid":"1.1"`)), err: "direct builder minimum bid is invalid"},
		{name: "BoostMissing", input: config(validBuilder(`,"builder_boost_factor":null`)), err: "direct builder boost factor is missing"},
		{name: "BuildersNull", input: []byte(`{"version":2,"epbs_builder_config":{"builders":null}}`), err: "ePBS direct builders must be an array"},
		{name: "NullBuilder", input: config("null"), err: "direct builder 0 is null"},
		{name: "DuplicateBuilder", input: config(validBuilder("") + "," + validBuilder("")), err: "direct builder 1 duplicates an earlier URL and authorization"},
		{name: "RootMinimumNull", input: []byte(`{"version":2,"epbs_builder_config":{"min_bid":null}}`), err: "ePBS minimum bid must be a decimal string"},
		{name: "RootBoostNull", input: []byte(`{"version":2,"epbs_builder_config":{"builder_boost_factor":null}}`), err: "ePBS builder boost factor must be an unsigned integer"},
		{name: "RootMinimumInvalid", input: []byte(`{"version":2,"epbs_builder_config":{"min_bid":"18446744073709551616"}}`), err: "invalid ePBS minimum bid: strconv.ParseUint: parsing \"18446744073709551616\": value out of range"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var parsed v2.ExecutionConfig
			err := json.Unmarshal(test.input, &parsed)
			expectedPrefix := "invalid JSON: invalid ePBS builder config: "
			if test.name == "RootMinimumNull" || test.name == "RootBoostNull" || test.name == "RootMinimumInvalid" || test.name == "BuildersNull" || test.name == "NullBuilder" || test.name == "DuplicateBuilder" {
				expectedPrefix = "invalid JSON: "
			}
			require.EqualError(t, err, expectedPrefix+test.err)
			require.NotContains(t, err.Error(), "deadbeef")
			require.NotContains(t, err.Error(), "secret")
		})
	}

	t.Run("ProtocolBoundaries", func(t *testing.T) {
		pubkeys := make([]string, 64)
		for i := range pubkeys {
			pubkeys[i] = fmt.Sprintf("%q", validPubkey)
		}
		builder := fmt.Sprintf(`{"url":"https://builder.example/%s","auth_data":"0x%s","builder_pubkeys":[%s],"max_execution_payment":"%d","min_bid":"%d","builder_boost_factor":%d}`,
			strings.Repeat("a", 2024), strings.Repeat("11", 4096), strings.Join(pubkeys, ","), uint64(math.MaxUint64), uint64(math.MaxUint64), uint64(math.MaxUint64))
		var parsed v2.ExecutionConfig
		require.NoError(t, json.Unmarshal(config(builder), &parsed))
	})

	t.Run("EmptyPubkeyAllowlist", func(t *testing.T) {
		var parsed v2.ExecutionConfig
		require.NoError(t, json.Unmarshal(config(validBuilder(`,"builder_pubkeys":[]`)), &parsed))
	})

	t.Run("TooManyBuilders", func(t *testing.T) {
		builders := make([]string, 65)
		for i := range builders {
			builders[i] = validBuilder("")
		}
		input := fmt.Appendf(nil, `{"version":2,"epbs_builder_config":{"builders":[%s]}}`, strings.Join(builders, ","))
		var parsed v2.ExecutionConfig
		err := json.Unmarshal(input, &parsed)
		require.EqualError(t, err, "invalid JSON: ePBS builder config has more than 64 direct builders")
		require.NotContains(t, err.Error(), "deadbeef")
	})

	t.Run("TooManyPubkeys", func(t *testing.T) {
		pubkeys := make([]string, 65)
		for i := range pubkeys {
			pubkeys[i] = fmt.Sprintf("%q", validPubkey)
		}
		var parsed v2.ExecutionConfig
		err := json.Unmarshal(config(validBuilder(fmt.Sprintf(`,"builder_pubkeys":[%s]`, strings.Join(pubkeys, ",")))), &parsed)
		require.EqualError(t, err, "invalid JSON: invalid ePBS builder config: direct builder public key allowlist has more than 64 entries")
		require.NotContains(t, err.Error(), "deadbeef")
	})
}
