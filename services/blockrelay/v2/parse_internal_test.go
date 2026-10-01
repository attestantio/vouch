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

package v2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFirstSet(t *testing.T) {
	first := uint64(1)
	second := uint64(2)

	require.Equal(t, uint64(1), firstSet(9, &first, &second))
	require.Equal(t, uint64(2), firstSet(9, nil, &second))
	require.Equal(t, uint64(9), firstSet[uint64](9, nil, nil))
}
