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

package beaconblockproposer_test

import (
	"errors"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/stretchr/testify/require"
)

func TestSafeError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		sensitive []string
		expected  string
	}{
		{
			name:     "Plain",
			err:      errors.New("request failed"),
			expected: "request failed",
		},
		{
			name:     "URL",
			err:      errors.New("request to https://user:secret@example.com/path?token=secret failed"),
			expected: "request to <redacted> failed",
		},
		{
			name:      "ConfiguredEndpoint",
			err:       errors.New("dial user:secret@example.com failed"),
			sensitive: []string{"user:secret@example.com"},
			expected:  "dial <redacted> failed",
		},
		{
			name: "RemoteResponseBody",
			err: api.Error{
				Method:     "POST",
				StatusCode: 500,
				Data:       []byte(`{"auth_data":"private-auth-value"}`),
			},
			expected: "POST failed with status 500",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, beaconblockproposer.SafeError(test.err, test.sensitive...))
		})
	}
}
