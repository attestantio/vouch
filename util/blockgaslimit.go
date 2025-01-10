// Copyright © 2024 Attestant Limited.
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

// ExpectedGasLimit returns the expected gas limit for a block given the gas limit of the previous block and the target gas limit
// for the subsequent proposer.
func ExpectedGasLimit(
	lastBlockGasLimit uint64,
	targetGasLimit uint64,
) uint64 {
	// Calculate the expected gas limit from the previous gas limit and the relay gas limit.
	expectedGasLimit := uint64(0)
	delta := lastBlockGasLimit/1024 - 1
	switch {
	case lastBlockGasLimit < targetGasLimit:
		// We expect the gas limit to rise.
		expectedGasLimit = lastBlockGasLimit + delta
		if expectedGasLimit > targetGasLimit {
			expectedGasLimit = targetGasLimit
		}
	case lastBlockGasLimit == targetGasLimit:
		// We expect the gas limit to stay the same.
	case lastBlockGasLimit > targetGasLimit:
		// We expect the gas limit to fall.
		expectedGasLimit = lastBlockGasLimit - delta
		if expectedGasLimit < targetGasLimit {
			expectedGasLimit = targetGasLimit
		}
	}

	return expectedGasLimit
}
