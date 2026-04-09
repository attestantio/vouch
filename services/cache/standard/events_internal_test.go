// Copyright © 2022 - 2026 Attestant Limited.
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
	"testing"

	consensusclient "github.com/attestantio/go-eth2-client"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestHandleHead(t *testing.T) {
	tests := []struct {
		name                       string
		beaconBlockHeadersProvider consensusclient.BeaconBlockHeadersProvider
		signedBeaconBlockProvider  consensusclient.SignedBeaconBlockProvider
		expectSlotCached           bool
	}{
		{
			name:                       "HeaderAndBlockSuccess",
			beaconBlockHeadersProvider: mock.NewBeaconBlockHeadersProvider(),
			signedBeaconBlockProvider:  mock.NewSignedBeaconBlockProvider(),
			expectSlotCached:           true,
		},
		{
			name:                       "HeaderSuccessBlockPruned",
			beaconBlockHeadersProvider: mock.NewBeaconBlockHeadersProvider(),
			signedBeaconBlockProvider:  mock.NewErroringSignedBeaconBlockProvider(),
			expectSlotCached:           true,
		},
		{
			name:                       "HeaderFailure",
			beaconBlockHeadersProvider: mock.NewErroringBeaconBlockHeadersProvider(),
			signedBeaconBlockProvider:  mock.NewSignedBeaconBlockProvider(),
			expectSlotCached:           false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()

			s := &Service{
				log:                        zerolog.New(zerolog.NewTestWriter(t)),
				beaconBlockHeadersProvider: test.beaconBlockHeadersProvider,
				signedBeaconBlockProvider:  test.signedBeaconBlockProvider,
				blockRootToSlot:            make(map[phase0.Root]phase0.Slot),
				blockGasLimits:             make(map[uint64]uint64),
			}

			blockRoot := phase0.Root([32]byte{0x01})
			headEvent := &apiv1.HeadEvent{
				Slot:  100,
				Block: blockRoot,
			}

			s.handleHead(ctx, headEvent)

			s.blockRootToSlotMu.RLock()
			_, cached := s.blockRootToSlot[blockRoot]
			s.blockRootToSlotMu.RUnlock()

			if test.expectSlotCached {
				require.True(t, cached, "block root to slot should be cached")
			} else {
				require.False(t, cached, "block root to slot should not be cached")
			}
		})
	}
}
