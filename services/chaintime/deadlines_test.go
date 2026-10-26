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

package chaintime_test

import (
	"testing"
	"time"

	"github.com/attestantio/vouch/services/chaintime"
	"github.com/stretchr/testify/require"
)

func TestGloasSlotDuration(t *testing.T) {
	tests := []struct {
		name     string
		raw      any
		expected time.Duration
	}{
		{name: "Served", raw: uint64(6000), expected: 6 * time.Second},
		{name: "Missing", expected: 12 * time.Second},
		{name: "Zero", raw: uint64(0), expected: 12 * time.Second},
		{name: "Malformed", raw: "6000", expected: 12 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := map[string]any{}
			if test.raw != nil {
				spec["SLOT_DURATION_MS"] = test.raw
			}
			require.Equal(t, test.expected, chaintime.GloasSlotDuration(spec, 12*time.Second))
		})
	}
}

func TestDueBPS(t *testing.T) {
	tests := []struct {
		name     string
		raw      any
		expected time.Duration
	}{
		{name: "Served", raw: uint64(2500), expected: 3 * time.Second},
		{name: "WholeSlot", raw: uint64(10000), expected: 12 * time.Second},
		{name: "Missing", expected: time.Second},
		{name: "Zero", raw: uint64(0), expected: time.Second},
		{name: "OutOfRange", raw: uint64(10001), expected: time.Second},
		{name: "Malformed", raw: "2500", expected: time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := map[string]any{}
			if test.raw != nil {
				spec["ATTESTATION_DUE_BPS_GLOAS"] = test.raw
			}
			require.Equal(t, test.expected, chaintime.DueBPS(spec, "ATTESTATION_DUE_BPS_GLOAS", 12*time.Second, time.Second))
		})
	}
}
