// Copyright © 2020 Attestant Limited.
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
	"fmt"
	"time"

	api "github.com/attestantio/go-eth2-client/api/v1"
)

// HandleHeadEvent handles the "head" events from the beacon node.
func (s *Service) HandleHeadEvent(event *api.Event) {
	ctx := context.Background()
	data := event.Data.(*api.HeadEvent)
	log.Trace().Uint64("slot", uint64(data.Slot)).Msg("Received head event")

	if data.Slot != s.chainTimeService.CurrentSlot() {
		return
	}
	s.monitor.BlockDelay(time.Since(s.chainTimeService.StartOfSlot(data.Slot)))

	// We give the block half a second to propagate around the rest of the network before
	// kicking off attestations for the block's slot.
	time.Sleep(500 * time.Millisecond)
	jobName := fmt.Sprintf("Beacon block attestations for slot %d", data.Slot)
	if s.scheduler.JobExists(ctx, jobName) {
		log.Trace().Uint64("slot", uint64(data.Slot)).Msg("Kicking off attestations for slot early due to receiving relevant block")
		if err := s.scheduler.RunJobIfExists(ctx, jobName); err != nil {
			log.Error().Str("job", jobName).Err(err).Msg("Failed to run attester job")
		}
	}

	// Remove old subscriptions if present.
	delete(s.subscriptionInfos, s.chainTimeService.SlotToEpoch(data.Slot)-2)
}
