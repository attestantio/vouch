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

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// ExecutionChainHead provides the execution chain head.
func (s *Service) ExecutionChainHead(_ context.Context) (phase0.Hash32, uint64) {
	s.executionChainHeadMu.RLock()
	defer s.executionChainHeadMu.RUnlock()
	return s.executionChainHeadRoot, s.executionChainHeadHeight
}

// setExecutionChainHead sets the execution chain head.
func (s *Service) setExecutionChainHead(root phase0.Hash32, height uint64) {
	s.executionChainHeadMu.Lock()
	s.executionChainHeadRoot = root
	s.executionChainHeadHeight = height
	monitorExecutionChainHeadUpdated(height)
	s.executionChainHeadMu.Unlock()
}
