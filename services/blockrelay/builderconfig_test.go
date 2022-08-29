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

func TestBuilderConfig(t *testing.T) {
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
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type blockrelay.builderConfigJSON",
		},
		{
			name:  "EnabledWrongType",
			input: []byte(`{"enabled":"true","relays":["server1.example.com","server2.example.com"]}`),
			err:   "invalid JSON: json: cannot unmarshal string into Go struct field builderConfigJSON.enabled of type bool",
		},
		{
			name:  "EnabledInvalid",
			input: []byte(`{"enabled":maybe,"relays":["server1.example.com","server2.example.com"]}`),
			err:   "invalid character 'm' looking for beginning of value",
		},
		{
			name:  "RelaysMissing",
			input: []byte(`{"enabled":true}`),
			err:   "relays missing",
		},
		{
			name:  "RelaysWrongType",
			input: []byte(`{"enabled":true,"relays":true}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field builderConfigJSON.relays of type []string",
		},
		{
			name:  "RelayWrongType",
			input: []byte(`{"enabled":true,"relays":[true, true]}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field builderConfigJSON.relays of type string",
		},
		{
			name:  "Good",
			input: []byte(`{"enabled":true,"relays":["server1.example.com","server2.example.com"]}`),
		},
		{
			name:  "GoodDisabled",
			input: []byte(`{"enabled":false}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res blockrelay.BuilderConfig
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
