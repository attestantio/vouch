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
	"testing"

	mockproposalpreparer "github.com/attestantio/vouch/services/proposalpreparer/mock"
	"github.com/stretchr/testify/require"
)

// resetReconnectCallbacks clears the registered callbacks, restoring them when the test ends.
func resetReconnectCallbacks(t *testing.T) {
	t.Helper()

	reconnectCallbacksMu.Lock()
	existing := reconnectCallbacks
	reconnectCallbacks = nil
	reconnectCallbacksMu.Unlock()

	t.Cleanup(func() {
		reconnectCallbacksMu.Lock()
		reconnectCallbacks = existing
		reconnectCallbacksMu.Unlock()
	})
}

func TestOnClientActiveWithoutCallbacks(t *testing.T) {
	resetReconnectCallbacks(t)

	require.NotPanics(t, func() {
		onClientActive(context.Background(), "http://localhost:5051")
	})
}

func TestOnClientActiveCallsCallbacksWithAddress(t *testing.T) {
	resetReconnectCallbacks(t)

	addresses := make([]string, 0)
	addReconnectCallback(func(_ context.Context, address string) {
		addresses = append(addresses, address)
	})
	addReconnectCallback(func(_ context.Context, address string) {
		addresses = append(addresses, address)
	})

	onClientActive(context.Background(), "http://localhost:5051")

	require.Equal(t, []string{"http://localhost:5051", "http://localhost:5051"}, addresses)
}

func TestOnClientActiveCallsCallbacksOnEachActivation(t *testing.T) {
	resetReconnectCallbacks(t)

	calls := 0
	addReconnectCallback(func(_ context.Context, _ string) {
		calls++
	})

	onClientActive(context.Background(), "http://localhost:5051")
	onClientActive(context.Background(), "http://localhost:5052")

	require.Equal(t, 2, calls)
}

// TestRegisterProposalPreparationsUpdaterWithoutPreparer confirms that a nil preparer, as
// provided before the bellatrix fork, does not register a callback that would panic when a
// client becomes active.
func TestRegisterProposalPreparationsUpdaterWithoutPreparer(t *testing.T) {
	resetReconnectCallbacks(t)

	registerProposalPreparationsUpdater(context.Background(), nil)

	reconnectCallbacksMu.RLock()
	registered := len(reconnectCallbacks)
	reconnectCallbacksMu.RUnlock()
	require.Equal(t, 0, registered)

	require.NotPanics(t, func() {
		onClientActive(context.Background(), "http://localhost:5051")
	})
}

// ctxCapturingProposalPreparer records the context with which it was last called.
type ctxCapturingProposalPreparer struct {
	ctx context.Context
}

func (s *ctxCapturingProposalPreparer) UpdatePreparations(ctx context.Context) error {
	s.ctx = ctx

	return nil
}

// TestRegisterProposalPreparationsUpdaterIgnoresCallbackContext confirms that the updates use the
// service context rather than the callback's.  A client checks its connection state on the way in
// to a request that finds it inactive, so the callback can be invoked with that request's context,
// which is cancelled as soon as the request completes; using it cancels the preparations in flight.
func TestRegisterProposalPreparationsUpdaterIgnoresCallbackContext(t *testing.T) {
	resetReconnectCallbacks(t)

	preparer := &ctxCapturingProposalPreparer{}
	registerProposalPreparationsUpdater(context.Background(), preparer)

	// Fire the callback with a context that is already cancelled, as a completed request's is.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	onClientActive(cancelledCtx, "http://localhost:5051")

	require.NotNil(t, preparer.ctx)
	require.NoError(t, preparer.ctx.Err())
}

func TestRegisterProposalPreparationsUpdaterWithPreparer(t *testing.T) {
	resetReconnectCallbacks(t)

	registerProposalPreparationsUpdater(context.Background(), mockproposalpreparer.New())

	reconnectCallbacksMu.RLock()
	registered := len(reconnectCallbacks)
	reconnectCallbacksMu.RUnlock()
	require.Equal(t, 1, registered)

	require.NotPanics(t, func() {
		onClientActive(context.Background(), "http://localhost:5051")
	})
}

// TestAddReconnectCallbackDuringDispatch confirms that a callback registered while callbacks
// are being dispatched does not deadlock, as clients can become active at any time.
func TestAddReconnectCallbackDuringDispatch(t *testing.T) {
	resetReconnectCallbacks(t)

	addReconnectCallback(func(_ context.Context, _ string) {
		addReconnectCallback(func(_ context.Context, _ string) {})
	})

	require.NotPanics(t, func() {
		onClientActive(context.Background(), "http://localhost:5051")
	})

	reconnectCallbacksMu.RLock()
	defer reconnectCallbacksMu.RUnlock()
	require.Len(t, reconnectCallbacks, 2)
}
