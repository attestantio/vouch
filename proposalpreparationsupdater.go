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

package main

import (
	"context"
	"sync"
	"time"

	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/proposalpreparer"
	"github.com/attestantio/vouch/util"
)

// proposalPreparationsUpdater updates proposal preparations when a consensus client becomes
// synced, in addition to the controller's once-per-epoch update.
//
// Beacon nodes hold proposal preparations in memory, so a node that restarts has none until
// they are next submitted.  The per-epoch update skips a node that is unavailable when it runs,
// so without this a node can be back and synced for up to an epoch with no preparations, and
// a block it builds locally in that window pays its own default fee recipient.
//
// A single change of connection state can be reported several times, so updates are rate
// limited: the first trigger updates straight away, and any triggers seen during the following
// cooldown of one slot result in at most one further update when the cooldown ends.  The
// per-epoch update is separate, and is not affected by the cooldown.
type proposalPreparationsUpdater struct {
	chainTime chaintime.Service
	preparer  proposalpreparer.Service

	// running is true from the first trigger until a cooldown ends with nothing pending.
	running bool
	// pending is true if a trigger was seen while running, with pendingAddress its node.
	pending        bool
	pendingAddress string
	// Protects running, pending and pendingAddress.
	mu sync.Mutex
}

// startProposalPreparationsUpdater updates proposal preparations when a consensus client
// becomes synced, until the supplied context is done.
//
// The supplied context is used for the updates.  The context passed to a client's hooks can be
// that of the request that triggered the connection state check, which may already be cancelled.
func startProposalPreparationsUpdater(ctx context.Context,
	chainTime chaintime.Service,
	preparer proposalpreparer.Service,
) {
	updater := &proposalPreparationsUpdater{
		chainTime: chainTime,
		preparer:  preparer,
	}
	setClientSyncedHandler(func(address string) {
		updater.triggerUpdate(ctx, address)
	})
}

// triggerUpdate requests an update following the consensus client at the given address becoming
// synced.  It does not block.
func (u *proposalPreparationsUpdater) triggerUpdate(ctx context.Context, address string) {
	if ctx.Err() != nil {
		return
	}

	u.mu.Lock()
	if u.running {
		u.pending = true
		u.pendingAddress = address
		u.mu.Unlock()
		log.Debug().
			Str("beacon_node", util.BeaconNodeName(address)).
			Msg("Consensus client synced; proposal preparations updated recently, so updating again after the cooldown")

		return
	}
	u.running = true
	u.mu.Unlock()

	go u.runUpdates(ctx, address)
}

// runUpdates updates proposal preparations, then repeats once per cooldown for as long as further
// triggers are seen.  The lock is never held across an update, so a stalled update does not
// block triggers or the per-epoch update.
func (u *proposalPreparationsUpdater) runUpdates(ctx context.Context, address string) {
	for {
		u.updatePreparations(ctx, address)

		timer := time.NewTimer(u.cooldown())
		select {
		case <-ctx.Done():
			timer.Stop()
			u.mu.Lock()
			u.running = false
			u.pending = false
			u.mu.Unlock()

			return
		case <-timer.C:
		}

		u.mu.Lock()
		if !u.pending {
			u.running = false
			u.mu.Unlock()

			return
		}
		address = u.pendingAddress
		u.pending = false
		u.mu.Unlock()
	}
}

// updatePreparations updates proposal preparations on all proposing nodes.  UpdatePreparations builds
// the preparations afresh on each call, so each update reflects the current validators.
func (u *proposalPreparationsUpdater) updatePreparations(ctx context.Context, address string) {
	if ctx.Err() != nil {
		return
	}

	// As with the scheduled update, there is nothing to prepare before the bellatrix fork.  An
	// unscheduled fork returns the far future epoch, so is also skipped.
	if u.chainTime.CurrentEpoch() < u.chainTime.HardForkEpoch(ctx, "BELLATRIX_FORK_EPOCH") {
		log.Trace().Msg("Not at bellatrix fork epoch; not updating proposal preparations")

		return
	}

	name := util.BeaconNodeName(address)
	log.Info().Str("beacon_node", name).Msg("Consensus client synced; updating proposal preparations")
	if err := u.preparer.UpdatePreparations(ctx); err != nil {
		log.Error().Str("beacon_node", name).Err(err).Msg("Failed to update proposal preparations after consensus client synced")
	}
}

// cooldown returns the minimum time between updates, which is the duration of the current slot.
func (u *proposalPreparationsUpdater) cooldown() time.Duration {
	currentSlot := u.chainTime.CurrentSlot()

	return u.chainTime.StartOfSlot(currentSlot + 1).Sub(u.chainTime.StartOfSlot(currentSlot))
}
