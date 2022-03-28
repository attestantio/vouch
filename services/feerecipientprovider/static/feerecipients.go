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

package static

import (
	"context"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// FeeRecipients returns the fee recipients for the given validators.
func (s *Service) FeeRecipients(_ context.Context,
	indices []phase0.ValidatorIndex,
) (
	map[phase0.ValidatorIndex]bellatrix.ExecutionAddress,
	error,
) {
	started := time.Now()

	res := make(map[phase0.ValidatorIndex]bellatrix.ExecutionAddress, len(indices))
	for _, index := range indices {
		feeRecipient, exists := s.feeRecipients[index]
		if exists {
			res[index] = feeRecipient
		} else {
			res[index] = s.defaultFeeRecipient
		}
	}

	feeRecipientsCompleted(started, "succeeded")
	return res, nil
}
