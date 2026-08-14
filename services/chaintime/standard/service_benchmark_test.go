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

package standard_test

import (
	"context"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

var benchmarkForkEpoch phase0.Epoch

func BenchmarkHardForkEpoch(b *testing.B) {
	ctx := context.Background()
	specProvider := newMutableSpecProvider(map[string]any{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
		"GLOAS_FORK_EPOCH": uint64(1_000_000),
	})
	service := createMutableSpecService(b, specProvider)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkForkEpoch = service.HardForkEpoch(ctx, "GLOAS_FORK_EPOCH")
	}
}
