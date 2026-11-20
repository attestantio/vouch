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
	"sync/atomic"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/stretchr/testify/require"
)

const updaterSlotsPerEpoch = 32

// updaterChainTime is a chain time service with a fixed current epoch, bellatrix fork epoch and
// slot duration.
type updaterChainTime struct {
	genesis            time.Time
	slotDuration       time.Duration
	currentEpoch       phase0.Epoch
	bellatrixForkEpoch phase0.Epoch
	// bellatrixLookupLimit, if set, is the number of bellatrix fork epoch lookups that succeed.
	// Later lookups return the far future epoch, as chaintime does when the spec request fails.
	bellatrixLookupLimit int32
	bellatrixLookups     atomic.Int32
}

func (c *updaterChainTime) GenesisTime() time.Time {
	return c.genesis
}

func (c *updaterChainTime) StartOfSlot(slot phase0.Slot) time.Time {
	return c.genesis.Add(time.Duration(slot) * c.slotDuration)
}

func (c *updaterChainTime) StartOfEpoch(epoch phase0.Epoch) time.Time {
	return c.StartOfSlot(c.FirstSlotOfEpoch(epoch))
}

func (c *updaterChainTime) CurrentSlot() phase0.Slot {
	return c.FirstSlotOfEpoch(c.currentEpoch)
}

func (c *updaterChainTime) CurrentEpoch() phase0.Epoch {
	return c.currentEpoch
}

func (*updaterChainTime) SlotToEpoch(slot phase0.Slot) phase0.Epoch {
	return phase0.Epoch(slot / updaterSlotsPerEpoch)
}

func (*updaterChainTime) FirstSlotOfEpoch(epoch phase0.Epoch) phase0.Slot {
	return phase0.Slot(epoch * updaterSlotsPerEpoch)
}

func (c *updaterChainTime) HardForkEpoch(_ context.Context, hardForkName string) phase0.Epoch {
	if hardForkName == "BELLATRIX_FORK_EPOCH" {
		lookups := c.bellatrixLookups.Add(1)
		if c.bellatrixLookupLimit > 0 && lookups > c.bellatrixLookupLimit {
			return chaintime.FarFutureEpoch
		}

		return c.bellatrixForkEpoch
	}

	return chaintime.FarFutureEpoch
}

// postBellatrixChainTime returns a chain time service past the bellatrix fork, with the given
// slot duration, which is also the updater's cooldown.
func postBellatrixChainTime(slotDuration time.Duration) *updaterChainTime {
	return &updaterChainTime{
		genesis:            time.Now().Add(-time.Hour),
		slotDuration:       slotDuration,
		currentEpoch:       10,
		bellatrixForkEpoch: 5,
	}
}

// preparationsUpdate is a call to UpdatePreparations.
type preparationsUpdate struct {
	ctx context.Context
	at  time.Time
}

// recordingProposalPreparer records each call to UpdatePreparations.  If release is set, each
// call waits until release is closed or the call's context is done.
type recordingProposalPreparer struct {
	updates chan preparationsUpdate
	release chan struct{}
}

func newRecordingProposalPreparer() *recordingProposalPreparer {
	return &recordingProposalPreparer{
		updates: make(chan preparationsUpdate, 100),
	}
}

func (p *recordingProposalPreparer) UpdatePreparations(ctx context.Context) error {
	p.updates <- preparationsUpdate{ctx: ctx, at: time.Now()}
	if p.release != nil {
		select {
		case <-p.release:
		case <-ctx.Done():
		}
	}

	return nil
}

// requireUpdate waits for the next update, failing if none arrives within the timeout.
func requireUpdate(t *testing.T, preparer *recordingProposalPreparer, timeout time.Duration) preparationsUpdate {
	t.Helper()

	select {
	case update := <-preparer.updates:
		return update
	case <-time.After(timeout):
		require.FailNow(t, "proposal preparations were not updated", "waited %s", timeout)
	}

	return preparationsUpdate{}
}

// requireNoUpdate fails if an update arrives within the given duration.
func requireNoUpdate(t *testing.T, preparer *recordingProposalPreparer, duration time.Duration) {
	t.Helper()

	select {
	case <-preparer.updates:
		require.FailNow(t, "proposal preparations were updated unexpectedly")
	case <-time.After(duration):
	}
}

// requireTriggerReturns fails if triggerUpdate does not return within a second.
func requireTriggerReturns(ctx context.Context, t *testing.T, updater *proposalPreparationsUpdater, address string) {
	t.Helper()

	returned := make(chan struct{})
	go func() {
		updater.triggerUpdate(ctx, address)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		require.FailNow(t, "trigger blocked", "address %s", address)
	}
}

// resetClientSyncedHandler clears the client synced handler, restoring it when the test ends.
func resetClientSyncedHandler(t *testing.T) {
	t.Helper()

	existing := clientSyncedHandler.Swap(nil)
	t.Cleanup(func() {
		clientSyncedHandler.Store(existing)
	})
}

func TestProposalPreparationsUpdaterUpdatesOnTrigger(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cooldown := 100 * time.Millisecond
	preparer := newRecordingProposalPreparer()
	updater := &proposalPreparationsUpdater{chainTime: postBellatrixChainTime(cooldown), preparer: preparer}

	requireTriggerReturns(ctx, t, updater, "beacon-1")
	requireUpdate(t, preparer, time.Second)
	requireNoUpdate(t, preparer, 3*cooldown)
}

// TestProposalPreparationsUpdaterLimitsUpdates confirms that a burst of triggers, as seen when
// one change of connection state is reported several times, results in one update straight
// away and one more after the cooldown.
func TestProposalPreparationsUpdaterLimitsUpdates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cooldown := 200 * time.Millisecond
	preparer := newRecordingProposalPreparer()
	updater := &proposalPreparationsUpdater{chainTime: postBellatrixChainTime(cooldown), preparer: preparer}

	started := time.Now()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			updater.triggerUpdate(ctx, "beacon-1")
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		require.FailNow(t, "triggers blocked")
	}

	first := requireUpdate(t, preparer, time.Second)
	require.Less(t, first.at.Sub(started), cooldown)
	second := requireUpdate(t, preparer, time.Second)
	require.GreaterOrEqual(t, second.at.Sub(first.at), cooldown)
	requireNoUpdate(t, preparer, 3*cooldown)

	// The updater is idle again, so a later trigger updates straight away.
	requireTriggerReturns(ctx, t, updater, "beacon-1")
	requireUpdate(t, preparer, time.Second)
}

// TestProposalPreparationsUpdaterUpdatesImmediatelyAfterCooldown confirms that a trigger after
// the cooldown has ended, with nothing pending, updates straight away.
func TestProposalPreparationsUpdaterUpdatesImmediatelyAfterCooldown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cooldown := 100 * time.Millisecond
	preparer := newRecordingProposalPreparer()
	updater := &proposalPreparationsUpdater{chainTime: postBellatrixChainTime(cooldown), preparer: preparer}

	requireTriggerReturns(ctx, t, updater, "beacon-1")
	requireUpdate(t, preparer, time.Second)
	requireNoUpdate(t, preparer, 3*cooldown)

	started := time.Now()
	requireTriggerReturns(ctx, t, updater, "beacon-2")
	update := requireUpdate(t, preparer, time.Second)
	require.Less(t, update.at.Sub(started), cooldown)
}

// TestProposalPreparationsUpdaterStalledUpdateDoesNotBlockTriggers confirms that no lock is held
// across an update, so a stalled update does not block later triggers.
func TestProposalPreparationsUpdaterStalledUpdateDoesNotBlockTriggers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	preparer := newRecordingProposalPreparer()
	preparer.release = make(chan struct{})
	defer close(preparer.release)
	updater := &proposalPreparationsUpdater{chainTime: postBellatrixChainTime(100 * time.Millisecond), preparer: preparer}

	requireTriggerReturns(ctx, t, updater, "beacon-1")
	requireUpdate(t, preparer, time.Second)

	// The first update is now stalled.
	requireTriggerReturns(ctx, t, updater, "beacon-2")
}

// TestProposalPreparationsUpdaterBellatrixFork confirms that proposal preparations are updated
// from the bellatrix fork epoch onwards, and not before it or when the fork is unscheduled.  The
// current epoch is 10.
func TestProposalPreparationsUpdaterBellatrixFork(t *testing.T) {
	tests := []struct {
		name               string
		bellatrixForkEpoch phase0.Epoch
		updated            bool
	}{
		{
			name:               "BeforeFork",
			bellatrixForkEpoch: 11,
		},
		{
			name:               "AtFork",
			bellatrixForkEpoch: 10,
			updated:            true,
		},
		{
			name:               "Unscheduled",
			bellatrixForkEpoch: chaintime.FarFutureEpoch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			preparer := newRecordingProposalPreparer()
			updater := &proposalPreparationsUpdater{
				chainTime:          postBellatrixChainTime(100 * time.Millisecond),
				preparer:           preparer,
				bellatrixForkEpoch: test.bellatrixForkEpoch,
			}

			requireTriggerReturns(ctx, t, updater, "beacon-1")
			if test.updated {
				requireUpdate(t, preparer, time.Second)
			} else {
				requireNoUpdate(t, preparer, 300*time.Millisecond)
			}
		})
	}
}

// TestProposalPreparationsUpdaterReadsBellatrixForkEpochOnce confirms that the bellatrix fork
// epoch is read when the updater starts, so a lookup that fails later, as it can when a node that
// has just become synced again refetches the spec, does not stop the update.
func TestProposalPreparationsUpdaterReadsBellatrixForkEpochOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resetClientSyncedHandler(t)

	chainTime := postBellatrixChainTime(100 * time.Millisecond)
	chainTime.bellatrixLookupLimit = 1
	preparer := newRecordingProposalPreparer()
	startProposalPreparationsUpdater(ctx, chainTime, preparer)

	handler := clientSyncedHandler.Load()
	require.NotNil(t, handler)
	(*handler)("beacon-1")
	requireUpdate(t, preparer, time.Second)
}

// TestProposalPreparationsUpdaterUsesForkEpochReadAtStartup confirms that the fork epoch read
// when the updater starts is the one that gates updates.  The current epoch is 10.
func TestProposalPreparationsUpdaterUsesForkEpochReadAtStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resetClientSyncedHandler(t)

	chainTime := postBellatrixChainTime(100 * time.Millisecond)
	chainTime.bellatrixForkEpoch = 11
	preparer := newRecordingProposalPreparer()
	startProposalPreparationsUpdater(ctx, chainTime, preparer)

	handler := clientSyncedHandler.Load()
	require.NotNil(t, handler)
	(*handler)("beacon-1")
	requireNoUpdate(t, preparer, 300*time.Millisecond)
}

// TestProposalPreparationsUpdaterStopsWhenContextDone confirms that a pending update is
// dropped, and later triggers ignored, once the service context is done.
func TestProposalPreparationsUpdaterStopsWhenContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cooldown := 200 * time.Millisecond
	preparer := newRecordingProposalPreparer()
	updater := &proposalPreparationsUpdater{chainTime: postBellatrixChainTime(cooldown), preparer: preparer}

	requireTriggerReturns(ctx, t, updater, "beacon-1")
	requireUpdate(t, preparer, time.Second)

	// Leave an update pending for the end of the cooldown, then stop the service.
	requireTriggerReturns(ctx, t, updater, "beacon-2")
	cancel()
	requireNoUpdate(t, preparer, 3*cooldown)

	requireTriggerReturns(ctx, t, updater, "beacon-3")
	requireNoUpdate(t, preparer, 3*cooldown)
}
