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

package testutil

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// CreateValidatorIndexToCommitteeIndicesTestData creates sync committee test data for unit tests.
// We produce validators with indices 0-9 and each validator is part of committee indices `(validator index * 10) + n`, where n is 0 - 4.
// This satisfies that each validator can be included multiple times in a committee at different indices, but no 2 validators share the same committee Index.
func CreateValidatorIndexToCommitteeIndicesTestData() map[phase0.ValidatorIndex][]phase0.CommitteeIndex {
	validatorToCommitteeIndices := make(map[phase0.ValidatorIndex][]phase0.CommitteeIndex, 10)
	for validatorIndex := range uint64(10) {
		var committeeIndices []phase0.CommitteeIndex
		for committeeOffset := range uint64(5) {
			committeeIndex := validatorIndex*10 + committeeOffset
			committeeIndices = append(committeeIndices, phase0.CommitteeIndex(committeeIndex))
		}
		validatorToCommitteeIndices[phase0.ValidatorIndex(validatorIndex)] = committeeIndices
	}
	return validatorToCommitteeIndices
}
