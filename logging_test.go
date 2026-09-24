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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestInitLoggingHidesBeaconNodeAddress(t *testing.T) {
	original := zerologger.Logger
	originalLevel := zerolog.GlobalLevel()
	t.Cleanup(func() {
		zerologger.Logger = original
		zerolog.SetGlobalLevel(originalLevel)
		viper.Reset()
	})
	path := filepath.Join(t.TempDir(), "vouch.log")
	viper.Set("beacon-node-addresses", []string{"https://private.example:5052", "https://user:pw@second.example:5052/path"})
	viper.Set("log-file", path)

	require.NoError(t, initLogging())
	log.Error().Str("provider", "https://private.example:5052").Err(errors.New("dial https://private.example:5052 failed")).Msg("request failed")
	log.Error().Str("provider", "http://second.example:5052").Msg("normalized address")
	log.Error().Str("provider", "https://user:pw@second.example:5052/other").Msg("credential-bearing address")
	log.Error().Str("provider", "https://user:xxxxx@second.example:5052/other").Msg("normalized credentials")
	log.Error().Str("provider", "https://user:xxxxx@second.example:5052/path?token=hidden").Msg("URL with query")
	log.Error().Str("provider", "https://alternate:secret@second.example:5052/other").Msg("alternate credentials")
	output, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(output), "private.example")
	require.NotContains(t, string(output), "second.example")
	require.NotContains(t, string(output), "user:pw")
	require.NotContains(t, string(output), "user:xxxxx")
	require.NotContains(t, string(output), "/path")
	require.NotContains(t, string(output), "token=hidden")
	require.NotContains(t, string(output), "alternate:secret")
	require.Contains(t, string(output), "beacon-1")
	require.Contains(t, string(output), "beacon-2")
}
