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

package testutil

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

// AssertValidBLSPubKeyFormat validates that a string is a valid BLS public key format.
// Ethereum BLS public keys are 48 bytes, represented as 0x-prefixed hex (98 chars total).
func AssertValidBLSPubKeyFormat(t *testing.T, pubKeyStr string) {
	t.Helper()

	// Must have 0x prefix.
	require.True(t, strings.HasPrefix(pubKeyStr, "0x"),
		"BLS public key must have 0x prefix, got: %s", pubKeyStr)

	// Must be exactly 98 characters (0x + 96 hex chars for 48 bytes).
	require.Len(t, pubKeyStr, 98,
		"BLS public key must be 98 characters (0x + 96 hex), got length %d", len(pubKeyStr))

	// The hex portion must be valid hex.
	hexPart := pubKeyStr[2:]
	_, err := hex.DecodeString(hexPart)
	require.NoError(t, err, "BLS public key hex portion must be valid hex")

	// Verify it can be parsed back to a BLSPubKey.
	var parsedKey phase0.BLSPubKey
	err = parsedKey.UnmarshalJSON([]byte(`"` + pubKeyStr + `"`))
	require.NoError(t, err, "BLS public key must be parseable as phase0.BLSPubKey")
}
