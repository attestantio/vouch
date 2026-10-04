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

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestControllerDelayParameters(t *testing.T) {
	tests := []struct {
		name     string
		values   map[string]any
		warnings []string
		err      string
	}{
		{
			name: "unset",
		},
		{
			// Every key is spelled out here rather than read from the table, so a typo in the
			// table fails this test.
			name: "all set",
			values: map[string]any{
				"controller.max-attestation-delay":            "5s",
				"controller.attestation-aggregation-delay":    "7s",
				"controller.max-sync-committee-message-delay": "2s",
				"controller.sync-committee-aggregation-delay": 9 * time.Second,
				"controller.max-proposal-delay":               "1s",
			},
			warnings: []string{
				"controller.max-attestation-delay is deprecated and ignored for Gloas slots",
				"controller.attestation-aggregation-delay is deprecated and ignored for Gloas slots",
				"controller.max-sync-committee-message-delay is deprecated and ignored for Gloas slots",
				"controller.sync-committee-aggregation-delay is deprecated and ignored for Gloas slots",
			},
		},
		{
			name: "zero values",
			values: map[string]any{
				"controller.max-attestation-delay":         0,
				"controller.attestation-aggregation-delay": "0s",
			},
		},
		{
			name:   "malformed",
			values: map[string]any{"controller.max-attestation-delay": "abc"},
			err:    `invalid controller.max-attestation-delay "abc"`,
		},
		{
			name:   "space before unit",
			values: map[string]any{"controller.attestation-aggregation-delay": "4 s"},
			err:    `invalid controller.attestation-aggregation-delay "4 s"`,
		},
		{
			name:   "string without unit",
			values: map[string]any{"controller.max-sync-committee-message-delay": "4"},
			err:    `invalid controller.max-sync-committee-message-delay "4"`,
		},
		{
			name:   "number without unit",
			values: map[string]any{"controller.sync-committee-aggregation-delay": 4},
			err:    "invalid controller.sync-committee-aggregation-delay 4",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := log
			t.Cleanup(func() {
				log = original
				viper.Reset()
			})
			var buf bytes.Buffer
			log = zerolog.New(&buf)
			for key, value := range test.values {
				viper.Set(key, value)
			}

			params, err := controllerDelayParameters()
			if test.err != "" {
				require.ErrorContains(t, err, test.err)

				return
			}
			require.NoError(t, err)
			require.Len(t, params, 4)

			var warnings []string
			for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
				if line == "" {
					continue
				}
				var entry struct {
					Level   string `json:"level"`
					Message string `json:"message"`
				}
				require.NoError(t, json.Unmarshal([]byte(line), &entry))
				require.Equal(t, "warn", entry.Level)
				warnings = append(warnings, entry.Message)
			}
			require.Equal(t, test.warnings, warnings)
		})
	}
}
