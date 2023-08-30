// Copyright © 2022 Attestant Limited.
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

package util

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCalculateExtentSize(t *testing.T) {
	cpuExtentSize := 1024 / runtime.GOMAXPROCS(0)
	if 1024%runtime.GOMAXPROCS(0) != 0 {
		cpuExtentSize++
	}

	tests := []struct {
		name               string
		items              int
		desiredConcurrency int
		extentSize         int
	}{
		{
			name:               "ZeroItems",
			items:              0,
			desiredConcurrency: 0,
			extentSize:         1,
		},
		{
			name:               "ZeroDesired",
			items:              1,
			desiredConcurrency: 0,
			extentSize:         1,
		},
		{
			name:               "CPUs",
			items:              1024,
			desiredConcurrency: -1,
			extentSize:         cpuExtentSize,
		},
		{
			name:               "Specific",
			items:              1024,
			desiredConcurrency: 32,
			extentSize:         32, // items / desired
		},
		{
			name:               "RoundedUp",
			items:              1025,
			desiredConcurrency: 32,
			extentSize:         33, // items / desired (rounded up)
		},
		{
			name:               "BalancedExtent",
			items:              1023,
			desiredConcurrency: 32,
			extentSize:         31,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := calculateExtentSize(test.items, test.desiredConcurrency)
			require.Equal(t, test.extentSize, res)
		})
	}
}
