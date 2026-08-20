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

package logger

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHasLog(t *testing.T) {
	tests := []struct {
		name   string
		fields map[string]any
		match  bool
	}{
		{
			name: "MatchingTypedFields",
			fields: map[string]any{
				"active": true,
				"count":  uint64(2),
				"name":   "vouch",
			},
			match: true,
		},
		{
			name: "MismatchedField",
			fields: map[string]any{
				"count": uint64(3),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := &LogCapture{
				entries: []map[string]any{{
					"active": true,
					"count":  float64(2),
					"name":   "vouch",
				}},
			}

			require.Equal(t, test.match, capture.HasLog(test.fields))
		})
	}
}

// TestEntriesDuringConcurrentWrite reads Entries while another goroutine is still capturing
// output, which is how the multinode submitters log once their submission has already returned.
// The final length assertion also proves every write was captured, so the writes need no
// assertion of their own on the writing goroutine.
func TestEntriesDuringConcurrentWrite(t *testing.T) {
	capture := &LogCapture{
		entries: make([]map[string]any, 0),
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 128 {
			_, _ = fmt.Fprintf(capture, `{"message":"entry","index":%d}`, i)
		}
	})

	for range 128 {
		for _, entry := range capture.Entries() {
			require.Equal(t, "entry", entry["message"])
		}
	}
	wg.Wait()

	require.Len(t, capture.Entries(), 128)
}
