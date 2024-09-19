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

package cache

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// Service provides a cache for information.
type Service interface{}

// BlockRootToSlotProvider provides a mapping from block root to slot.
type BlockRootToSlotProvider interface {
	// BlockRootToSlot provides the slot for a given block root.
	BlockRootToSlot(ctx context.Context, root phase0.Root) (phase0.Slot, error)
}

// BlockRootToSlotSetter sets a known block root to its slot.
type BlockRootToSlotSetter interface {
	// SetBlockRootToSlot sets the block root to slot mapping.
	SetBlockRootToSlot(root phase0.Root, slot phase0.Slot)
}

// ExecutionChainHeadProvider provides the current execution chain head.
type ExecutionChainHeadProvider interface {
	// ExecutionChainHead provides the current execution chain head.
	ExecutionChainHead(ctx context.Context) (phase0.Hash32, uint64)
}
