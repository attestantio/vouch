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

package util_test

import (
	"strings"
	"testing"

	"github.com/attestantio/vouch/util"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestBeaconNodeLogWriterUsesUnknownForAmbiguousHost(t *testing.T) {
	viper.Set("beacon-node-addresses", []string{
		"https://shared.example:5052/first",
		"https://shared.example:5052/second",
	})
	t.Cleanup(func() { viper.Reset() })
	var output strings.Builder
	writer := util.BeaconNodeLogWriter(&output)
	_, err := writer.Write([]byte("request to http://shared.example:5052 failed"))
	require.NoError(t, err)
	require.Equal(t, "request to beacon-unknown failed", output.String())
}

func TestLookupBeaconNodeNameDoesNotExposeAmbiguousHost(t *testing.T) {
	viper.Set("beacon-node-addresses", []string{
		"https://shared.example:5052/first",
		"https://shared.example:5052/second",
	})
	t.Cleanup(func() { viper.Reset() })

	name, known := util.LookupBeaconNodeName("http://shared.example:5052")
	require.True(t, known)
	require.Equal(t, "beacon-unknown", name)
}
