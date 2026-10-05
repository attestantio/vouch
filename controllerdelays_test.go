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
	"reflect"
	"strings"
	"testing"
	"time"

	standardcontroller "github.com/attestantio/vouch/services/controller/standard"
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
			// Every key is spelled out here rather than read from the table, so a typo in a key
			// fails this test.  TestControllerDelayOptions pins each key to its option.
			name: "all set",
			values: map[string]any{
				"controller.max-attestation-delay":            "5s",
				"controller.attestation-aggregation-delay":    "7s",
				"controller.max-sync-committee-message-delay": "2s",
				"controller.sync-committee-aggregation-delay": "9s",
				"controller.max-proposal-delay":               "1s",
			},
			warnings: []string{
				"controller.max-attestation-delay is deprecated; it applies to pre-Gloas slots only and is ignored from the Gloas fork onwards",
				"controller.attestation-aggregation-delay is deprecated; it applies to pre-Gloas slots only and is ignored from the Gloas fork onwards",
				"controller.max-sync-committee-message-delay is deprecated; it applies to pre-Gloas slots only and is ignored from the Gloas fork onwards",
				"controller.sync-committee-aggregation-delay is deprecated; it applies to pre-Gloas slots only and is ignored from the Gloas fork onwards",
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
			// A time.Duration, as from SetDefault or a pflag, carries its unit.
			name: "durations",
			values: map[string]any{
				"controller.max-attestation-delay":         time.Duration(0),
				"controller.attestation-aggregation-delay": 4 * time.Second,
			},
			warnings: []string{
				"controller.attestation-aggregation-delay is deprecated; it applies to pre-Gloas slots only and is ignored from the Gloas fork onwards",
			},
		},
		{
			name:   "negative duration",
			values: map[string]any{"controller.max-attestation-delay": -4 * time.Second},
			err:    `invalid controller.max-attestation-delay "-4s"`,
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
		{
			// A negative delay would schedule the duty before its slot starts.
			name:   "negative",
			values: map[string]any{"controller.max-attestation-delay": "-4s"},
			err:    `invalid controller.max-attestation-delay "-4s"`,
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

// TestControllerDelayParametersConfigFormats reads the keys as each config file format decodes them.
// JSON decodes numbers to float64 and TOML to int64, where YAML gives int.
// The environment provides strings, found through AutomaticEnv as the keys have no default.
func TestControllerDelayParametersConfigFormats(t *testing.T) {
	tests := []struct {
		format string
		zero   string
		number string
	}{
		{format: "yaml", zero: "controller:\n  max-attestation-delay: 0\n", number: "controller:\n  max-attestation-delay: 4\n"},
		{format: "json", zero: `{"controller":{"max-attestation-delay":0}}`, number: `{"controller":{"max-attestation-delay":4}}`},
		{format: "toml", zero: "[controller]\nmax-attestation-delay = 0\n", number: "[controller]\nmax-attestation-delay = 4\n"},
	}

	for _, test := range tests {
		t.Run(test.format, func(t *testing.T) {
			original := log
			t.Cleanup(func() {
				log = original
				viper.Reset()
			})
			var buf bytes.Buffer
			log = zerolog.New(&buf)
			viper.SetConfigType(test.format)

			require.NoError(t, viper.ReadConfig(strings.NewReader(test.zero)))
			_, err := controllerDelayParameters()
			require.NoError(t, err)
			require.Empty(t, buf.String())

			require.NoError(t, viper.ReadConfig(strings.NewReader(test.number)))
			_, err = controllerDelayParameters()
			require.ErrorContains(t, err, "invalid controller.max-attestation-delay 4")
		})
	}

	t.Run("env", func(t *testing.T) {
		t.Cleanup(viper.Reset)
		viper.SetEnvPrefix("VOUCH")
		viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
		viper.AutomaticEnv()

		t.Setenv("VOUCH_CONTROLLER_MAX_ATTESTATION_DELAY", "0")
		delays, err := controllerDelays()
		require.NoError(t, err)
		require.Zero(t, delays[0])

		t.Setenv("VOUCH_CONTROLLER_MAX_ATTESTATION_DELAY", "4s")
		delays, err = controllerDelays()
		require.NoError(t, err)
		require.Equal(t, 4*time.Second, delays[0])

		t.Setenv("VOUCH_CONTROLLER_MAX_ATTESTATION_DELAY", "4")
		_, err = controllerDelays()
		require.ErrorContains(t, err, `invalid controller.max-attestation-delay "4"`)
	})
}

// TestControllerDelayOptions pins each key to the option that consumes it, as a swapped pair would
// silently swap the operator's deadlines.
func TestControllerDelayOptions(t *testing.T) {
	expected := map[string]func(time.Duration) standardcontroller.Parameter{
		"controller.max-attestation-delay":            standardcontroller.WithMaxAttestationDelay,
		"controller.attestation-aggregation-delay":    standardcontroller.WithAttestationAggregationDelay,
		"controller.max-sync-committee-message-delay": standardcontroller.WithMaxSyncCommitteeMessageDelay,
		"controller.sync-committee-aggregation-delay": standardcontroller.WithSyncCommitteeAggregationDelay,
	}
	require.Len(t, deprecatedControllerDelays, len(expected))
	for _, delay := range deprecatedControllerDelays {
		option, exists := expected[delay.key]
		require.True(t, exists, delay.key)
		require.Equal(t, reflect.ValueOf(option).Pointer(), reflect.ValueOf(delay.option).Pointer(), delay.key)
	}
}
