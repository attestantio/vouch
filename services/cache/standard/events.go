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
	"bytes"
	"context"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
)

// handleBlock handles a block update message.
func (s *Service) handleBlock(event *apiv1.Event) {
	if event.Data == nil {
		return
	}

	data := event.Data.(*apiv1.BlockEvent)
	s.log.Trace().Stringer("root", data.Block).Uint64("slot", uint64(data.Slot)).Msg("Received block event")

	s.SetBlockRootToSlot(data.Block, data.Slot)
}

// handleHead handles a head update message.
func (s *Service) handleHead(event *apiv1.Event) {
	if event.Data == nil {
		return
	}

	data := event.Data.(*apiv1.HeadEvent)
	s.log.Trace().Stringer("root", data.Block).Uint64("slot", uint64(data.Slot)).Msg("Received head event")

	blockResponse, err := s.signedBeaconBlockProvider.SignedBeaconBlock(context.Background(), &api.SignedBeaconBlockOpts{
		Block: data.Block.String(),
	})
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to obtain block")
		return
	}
	block := blockResponse.Data

	s.updateExecutionHeadFromBlock(block)
}

func (s *Service) updateExecutionHeadFromBlock(block *spec.VersionedSignedBeaconBlock) {
	switch block.Version {
	case spec.DataVersionPhase0, spec.DataVersionAltair:
		// No execution information available, nothing to do.
	case spec.DataVersionBellatrix:
		// Potentially execution information available.
		if block.Bellatrix != nil && block.Bellatrix.Message != nil && block.Bellatrix.Message.Body != nil {
			executionPayload := block.Bellatrix.Message.Body.ExecutionPayload
			if executionPayload != nil && !bytes.Equal(executionPayload.StateRoot[:], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
				s.log.Trace().Uint64("height", executionPayload.BlockNumber).Stringer("hash", executionPayload.BlockHash).Msg("Updating execution chain head")
				s.setExecutionChainHead(executionPayload.BlockHash, executionPayload.BlockNumber)
			}
		}
	case spec.DataVersionCapella:
		// Execution information available.
		executionPayload := block.Capella.Message.Body.ExecutionPayload
		if executionPayload != nil && !bytes.Equal(executionPayload.StateRoot[:], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
			s.log.Trace().Uint64("height", executionPayload.BlockNumber).Stringer("hash", executionPayload.BlockHash).Msg("Updating execution chain head")
			s.setExecutionChainHead(executionPayload.BlockHash, executionPayload.BlockNumber)
		}
	case spec.DataVersionDeneb:
		// Execution information available.
		executionPayload := block.Deneb.Message.Body.ExecutionPayload
		if executionPayload != nil && !executionPayload.StateRoot.IsZero() {
			s.log.Trace().Uint64("height", executionPayload.BlockNumber).Stringer("hash", executionPayload.BlockHash).Msg("Updating execution chain head")
			s.setExecutionChainHead(executionPayload.BlockHash, executionPayload.BlockNumber)
		}
	default:
		s.log.Error().Msg("Unhandled block version")
	}
}
