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

package beaconblockproposal_test

import (
	"errors"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/vouch/strategies/beaconblockproposal"
	"github.com/attestantio/vouch/testing/logger"
	zerologger "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

func TestLogProviderOutcome(t *testing.T) {
	tests := []struct {
		name     string
		outcome  *beaconblockproposal.ProviderOutcome
		expected map[string]any
		omitted  []string
	}{
		{
			name: "NoProposal",
			outcome: &beaconblockproposal.ProviderOutcome{
				Provider: "node",
				Outcome:  "error",
				Err:      errors.New("request to http://node.example:5052 failed"),
			},
			expected: map[string]any{
				"provider":         "node",
				"source":           "unknown",
				"value_known":      false,
				"payload_included": false,
				"error":            "request to <redacted> failed",
			},
			omitted: []string{"builder_index"},
		},
		{
			name: "MalformedGloas",
			outcome: &beaconblockproposal.ProviderOutcome{
				Provider: "node",
				Proposal: &api.VersionedEPBSProposal{Version: spec.DataVersionGloas, ExecutionPayloadIncluded: true},
				Outcome:  "rejected",
			},
			expected: map[string]any{"source": "unknown", "payload_included": false},
			omitted:  []string{"builder_index"},
		},
		{
			name: "PreGloas",
			outcome: &beaconblockproposal.ProviderOutcome{
				Provider: "node",
				Proposal: &api.VersionedEPBSProposal{Version: spec.DataVersionFulu, ExecutionPayloadIncluded: true},
				Outcome:  "accepted",
			},
			expected: map[string]any{"source": "self_build", "payload_included": true, "execution_value": "unknown"},
			omitted:  []string{"builder_index"},
		},
		{
			name: "BuilderBid",
			outcome: &beaconblockproposal.ProviderOutcome{
				Provider: "node",
				Proposal: withoutPayload(7),
				Outcome:  "accepted",
			},
			expected: map[string]any{"source": "p2p_builder", "builder_index": uint64(7), "payload_included": false},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			beaconblockproposal.LogProviderOutcome(zerologger.Logger, test.outcome)
			entries := capture.Entries()
			require.Len(t, entries, 1)
			for key, value := range test.expected {
				require.True(t, capture.HasLog(map[string]any{key: value}), "%s in %v", key, entries[0])
			}
			for _, key := range test.omitted {
				require.NotContains(t, entries[0], key)
			}
		})
	}
}
