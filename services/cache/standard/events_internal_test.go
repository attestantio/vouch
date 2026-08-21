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

package standard

import (
	"bytes"
	"context"
	"testing"

	consensusclient "github.com/attestantio/go-eth2-client"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestHandleHead(t *testing.T) {
	tests := []struct {
		name                      string
		signedBeaconBlockProvider consensusclient.SignedBeaconBlockProvider
	}{
		{
			name:                      "BlockSuccess",
			signedBeaconBlockProvider: mock.NewSignedBeaconBlockProvider(),
		},
		{
			name:                      "BlockPruned",
			signedBeaconBlockProvider: mock.NewErroringSignedBeaconBlockProvider(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()

			s := &Service{
				log:                       zerolog.New(zerolog.NewTestWriter(t)),
				signedBeaconBlockProvider: test.signedBeaconBlockProvider,
				blockRootToSlot:           make(map[phase0.Root]phase0.Slot),
				blockGasLimits:            make(map[uint64]uint64),
			}

			blockRoot := phase0.Root([32]byte{0x01})
			headEvent := &apiv1.HeadEvent{
				Slot:  100,
				Block: blockRoot,
			}

			s.handleHead(ctx, headEvent)

			s.blockRootToSlotMu.RLock()
			cachedSlot, cached := s.blockRootToSlot[blockRoot]
			s.blockRootToSlotMu.RUnlock()

			require.True(t, cached, "block root to slot should always be cached from head event")
			require.Equal(t, phase0.Slot(100), cachedSlot, "slot should come from head event")
		})
	}
}

func TestUpdateFromBlockGloas(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	previousRoot := phase0.Hash32{0x01}
	previousHeight := uint64(123)
	previousGasLimit := uint64(30_000_000)

	s := &Service{
		log:                      zerolog.New(&logs),
		executionChainHeadRoot:   previousRoot,
		executionChainHeadHeight: previousHeight,
		blockGasLimits: map[uint64]uint64{
			previousHeight: previousGasLimit,
		},
	}

	s.updateFromBlock(&spec.VersionedSignedBeaconBlock{
		Version: spec.DataVersionGloas,
		Gloas: &gloas.SignedBeaconBlock{
			Message: &gloas.BeaconBlock{
				Body: &gloas.BeaconBlockBody{
					SignedExecutionPayloadBid: &gloas.SignedExecutionPayloadBid{
						Message: &gloas.ExecutionPayloadBid{
							BlockHash: phase0.Hash32{0x02},
							GasLimit:  31_000_000,
						},
					},
				},
			},
		},
	})

	require.NotContains(t, logs.String(), "Unhandled block version")

	actualRoot, actualHeight := s.ExecutionChainHead(ctx)
	require.Equal(t, previousRoot, actualRoot)
	require.Equal(t, previousHeight, actualHeight)

	actualGasLimit, exists := s.BlockGasLimit(ctx, previousHeight)
	require.True(t, exists)
	require.Equal(t, previousGasLimit, actualGasLimit)

	s.blockGasLimitMu.RLock()
	defer s.blockGasLimitMu.RUnlock()
	require.Equal(t, map[uint64]uint64{previousHeight: previousGasLimit}, s.blockGasLimits)
}
