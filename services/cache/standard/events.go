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

package standard

import (
	"bytes"
	"context"
	"fmt"

	consensusclient "github.com/attestantio/go-eth2-client"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
)

// handleBlock handles a block update message.
func (s *Service) handleBlock(event *apiv1.Event) {
	if event.Data == nil {
		return
	}

	data := event.Data.(*apiv1.BlockEvent)
	log.Trace().Str("root", fmt.Sprintf("%#x", data.Block)).Uint64("slot", uint64(data.Slot)).Msg("Received block event")

	s.SetBlockRootToSlot(data.Block, data.Slot)
}

// handleHead handles a head update message.
func (s *Service) handleHead(event *apiv1.Event) {
	if event.Data == nil {
		return
	}

	data := event.Data.(*apiv1.HeadEvent)
	log.Trace().Str("root", fmt.Sprintf("%#x", data.Block)).Uint64("slot", uint64(data.Slot)).Msg("Received head event")

	block, err := s.consensusClient.(consensusclient.SignedBeaconBlockProvider).SignedBeaconBlock(context.Background(), fmt.Sprintf("%#x", data.Block))
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain head block")
		return
	}
	if block == nil {
		log.Warn().Uint64("slot", uint64(data.Slot)).Stringer("root", data.Block).Msg("Obtained nil head block")
		return
	}

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
				log.Trace().Uint64("height", executionPayload.BlockNumber).Str("hash", fmt.Sprintf("%#x", executionPayload.BlockHash)).Msg("Updating execution chain head")
				s.setExecutionChainHead(executionPayload.BlockHash, executionPayload.BlockNumber)
			}
		}
	case spec.DataVersionCapella:
		// Execution information available.
		executionPayload := block.Capella.Message.Body.ExecutionPayload
		if executionPayload != nil && !bytes.Equal(executionPayload.StateRoot[:], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
			log.Trace().Uint64("height", executionPayload.BlockNumber).Str("hash", fmt.Sprintf("%#x", executionPayload.BlockHash)).Msg("Updating execution chain head")
			s.setExecutionChainHead(executionPayload.BlockHash, executionPayload.BlockNumber)
		}
	default:
		log.Error().Msg("Unhandled block version")
	}
}
