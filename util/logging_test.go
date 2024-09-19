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

package util_test

import (
	"testing"

	"github.com/attestantio/vouch/util"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestLogLevel(t *testing.T) {
	zerologger.Logger = zerologger.Logger.Level(zerolog.DebugLevel)

	tests := []struct {
		name  string
		vars  map[string]string
		path  string
		level zerolog.Level
	}{
		{
			name:  "Empty",
			path:  "",
			level: zerolog.DebugLevel,
		},
		{
			name:  "Root",
			path:  ".",
			level: zerolog.DebugLevel,
		},
		{
			name: "TopLevel",
			vars: map[string]string{
				"log-level": "info",
			},
			path:  "",
			level: zerolog.InfoLevel,
		},
		{
			name: "SingleLevel",
			vars: map[string]string{
				"log-level": "info",
			},
			path:  "a",
			level: zerolog.InfoLevel,
		},
		{
			name: "MultiLevel",
			vars: map[string]string{
				"log-level": "info",
			},
			path:  "a.b.c",
			level: zerolog.InfoLevel,
		},
		{
			name: "Override",
			vars: map[string]string{
				"log-level":     "info",
				"a.b.log-level": "Warn",
			},
			path:  "a.b.c",
			level: zerolog.WarnLevel,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			viper.Reset()

			for k, v := range test.vars {
				viper.Set(k, v)
			}
			level := util.LogLevel(test.path)
			require.Equal(t, test.level, level)
		})
	}
}
