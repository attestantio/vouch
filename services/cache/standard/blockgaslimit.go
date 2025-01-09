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

package standard

import (
	"context"
)

// BlockGasLimit provides the block gas limit.
func (s *Service) BlockGasLimit(_ context.Context, height uint64) (uint64, bool) {
	s.blockGasLimitMu.RLock()
	defer s.blockGasLimitMu.RUnlock()
	limit, exists := s.blockGasLimits[height]

	return limit, exists
}

// setBlockGasLimit sets the block gas limit.
func (s *Service) setBlockGasLimit(height uint64, gasLimit uint64) {
	s.blockGasLimitMu.Lock()
	s.blockGasLimits[height] = gasLimit
	monitorBlockGasLimitEntriesUpdated(len(s.blockGasLimits))
	s.log.Trace().Uint64("height", height).Uint64("gas_limit", gasLimit).Msg("Stored gas limit for block")
	s.blockGasLimitMu.Unlock()
}

// cleanBlockGasLimit cleans out old entries in the cache.
func (s *Service) cleanBlockGasLimit(_ context.Context) {
	// Keep 2048 slots of information around, to cover most scenarios.
	safetyMargin := uint64(2048)
	s.executionChainHeadMu.RLock()
	executionChainHeadHeight := s.executionChainHeadHeight
	s.executionChainHeadMu.RUnlock()
	if executionChainHeadHeight < safetyMargin {
		return
	}

	minHeight := executionChainHeadHeight - safetyMargin

	s.blockGasLimitMu.Lock()
	cleaned := 0
	for height := range s.blockGasLimits {
		if height < minHeight {
			delete(s.blockGasLimits, height)
			cleaned++
		}
	}
	monitorBlockGasLimitEntriesUpdated(len(s.blockGasLimits))
	s.blockGasLimitMu.Unlock()

	s.log.Trace().Int("cleaned", cleaned).Msg("Cleaned block gas limit cache")
}
