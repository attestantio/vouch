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
	"testing"

	"github.com/attestantio/vouch/util"
	"github.com/stretchr/testify/require"
)

func TestBeaconNodeClientDetailsIgnoreUnknownAndUntrustedVersions(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{name: "Unknown", version: "unknown/v1.2.3"},
		{name: "EndpointInsteadOfVersion", version: "https://private.example:5052"},
		{name: "UnrecognizedVersion", version: "Lighthouse/host-private.example"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address := "https://" + test.name + ".example:5052"
			util.RecordBeaconNodeVersion(address, test.version)
			client, version := util.BeaconNodeClientDetails(address)
			require.Empty(t, client)
			require.Empty(t, version)
		})
	}
}
