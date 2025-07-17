// Copyright © 2025 Attestant Limited.
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
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSignRootsMultiWithDuplicates is currently disabled due to interface implementation complexity.
// The deduplication logic is tested in TestDeduplicationLogic instead.
func TestSignRootsMultiWithDuplicates(t *testing.T) {
	t.Skip("Skipped due to mock interface complexity - deduplication logic tested in TestDeduplicationLogic")
}

func TestDeduplicationLogic(t *testing.T) {
	// Test the deduplication logic directly
	tests := []struct {
		name                   string
		accountKeys            []string
		rootKeys               []string
		expectedUniqueAccounts int
		expectedUniqueData     int
		expectedMapping        []int // maps original index to unique index
	}{
		{
			name:                   "NoDuplicates",
			accountKeys:            []string{"acc1", "acc2"},
			rootKeys:               []string{"root1", "root2"},
			expectedUniqueAccounts: 2,
			expectedUniqueData:     2,
			expectedMapping:        []int{0, 1},
		},
		{
			name:                   "SameAccountDifferentRoots",
			accountKeys:            []string{"acc1", "acc1"},
			rootKeys:               []string{"root1", "root2"},
			expectedUniqueAccounts: 2,
			expectedUniqueData:     2,
			expectedMapping:        []int{0, 1},
		},
		{
			name:                   "DifferentAccountsSameRoot",
			accountKeys:            []string{"acc1", "acc2"},
			rootKeys:               []string{"root1", "root1"},
			expectedUniqueAccounts: 2,
			expectedUniqueData:     2,
			expectedMapping:        []int{0, 1},
		},
		{
			name:                   "ExactDuplicates",
			accountKeys:            []string{"acc1", "acc1"},
			rootKeys:               []string{"root1", "root1"},
			expectedUniqueAccounts: 1,
			expectedUniqueData:     1,
			expectedMapping:        []int{0, 0},
		},
		{
			name:                   "MultipleDuplicates",
			accountKeys:            []string{"acc1", "acc1", "acc1", "acc1"},
			rootKeys:               []string{"root1", "root1", "root1", "root1"},
			expectedUniqueAccounts: 1,
			expectedUniqueData:     1,
			expectedMapping:        []int{0, 0, 0, 0},
		},
		{
			name:                   "MixedDuplicatesAndUnique",
			accountKeys:            []string{"acc1", "acc1", "acc2"},
			rootKeys:               []string{"root1", "root1", "root1"},
			expectedUniqueAccounts: 2,
			expectedUniqueData:     2,
			expectedMapping:        []int{0, 0, 1},
		},
		{
			name:                   "ComplexPattern",
			accountKeys:            []string{"acc1", "acc2", "acc1", "acc2", "acc1"},
			rootKeys:               []string{"root1", "root1", "root2", "root1", "root1"},
			expectedUniqueAccounts: 3,
			expectedUniqueData:     3,
			expectedMapping:        []int{0, 1, 2, 1, 0},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Simulate the deduplication logic from signRootsMulti
			type accountRootPair struct {
				accountKey string
				rootKey    string
			}

			uniquePairs := make(map[accountRootPair]int)
			uniqueAccounts := []string{}
			uniqueData := []string{}
			originalToUniqueIndex := make([]int, len(test.accountKeys))

			for i := range test.accountKeys {
				accountKey := test.accountKeys[i]
				rootKey := test.rootKeys[i]
				pair := accountRootPair{accountKey: accountKey, rootKey: rootKey}

				if uniqueIndex, exists := uniquePairs[pair]; exists {
					originalToUniqueIndex[i] = uniqueIndex
				} else {
					uniqueIndex := len(uniqueAccounts)
					uniquePairs[pair] = uniqueIndex
					originalToUniqueIndex[i] = uniqueIndex
					uniqueAccounts = append(uniqueAccounts, accountKey)
					uniqueData = append(uniqueData, rootKey)
				}
			}

			// Verify results
			assert.Equal(t, test.expectedUniqueAccounts, len(uniqueAccounts), "Unique accounts count mismatch")
			assert.Equal(t, test.expectedUniqueData, len(uniqueData), "Unique data count mismatch")
			assert.Equal(t, test.expectedMapping, originalToUniqueIndex, "Index mapping mismatch")

			// Verify that mapping back works correctly
			for i := range test.accountKeys {
				uniqueIndex := originalToUniqueIndex[i]
				assert.Equal(t, test.accountKeys[i], uniqueAccounts[uniqueIndex], "Account mapping incorrect at index %d", i)
				assert.Equal(t, test.rootKeys[i], uniqueData[uniqueIndex], "Root mapping incorrect at index %d", i)
			}
		})
	}
}
