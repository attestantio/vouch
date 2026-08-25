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

package standard

import (
	"testing"

	builderapi "github.com/attestantio/go-builder-client/api"
	"github.com/stretchr/testify/require"
)

func TestRegistrationOpts(t *testing.T) {
	registrations := []*builderapi.VersionedSignedValidatorRegistration{{}, {}}

	tests := []struct {
		name          string
		registrations []*builderapi.VersionedSignedValidatorRegistration
	}{
		{
			name:          "Empty",
			registrations: []*builderapi.VersionedSignedValidatorRegistration{},
		},
		{
			name:          "Single",
			registrations: registrations[:1],
		},
		{
			name:          "Multiple",
			registrations: registrations,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := registrationOpts(test.registrations)

			require.Equal(t, test.registrations, opts.Registrations)
			// The timeout must be left unset so that the timeout configured for the client
			// applies.  A per-call timeout can only shorten the deadline, never extend it.
			require.Zero(t, opts.Common.Timeout)
		})
	}
}
