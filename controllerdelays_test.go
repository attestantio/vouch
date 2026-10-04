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
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestWarnDeprecatedControllerDelays(t *testing.T) {
	original := log
	t.Cleanup(func() {
		log = original
		viper.Reset()
	})
	var buf bytes.Buffer
	log = zerolog.New(&buf)

	viper.Set("controller.max-attestation-delay", 5*time.Second)
	viper.Set("controller.sync-committee-aggregation-delay", "9s")
	viper.Set("controller.attestation-aggregation-delay", 0)
	viper.Set("controller.max-proposal-delay", time.Second)

	warnDeprecatedControllerDelays()

	require.Equal(t, []string{
		`{"level":"warn","message":"controller.max-attestation-delay is deprecated and ignored for Gloas slots"}`,
		`{"level":"warn","message":"controller.sync-committee-aggregation-delay is deprecated and ignored for Gloas slots"}`,
	}, strings.Split(strings.TrimSpace(buf.String()), "\n"))
}
