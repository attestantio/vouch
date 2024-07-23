// Copyright © 2021 Attestant Limited.
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

package mock

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/synccommitteemessenger"
)

// Service is a mock sync committee contributor.
type Service struct {
	lastReported map[phase0.Slot]synccommitteemessenger.SlotData
}

// New creates a new mock sync committee contributor.
func New() *Service {
	return &Service{lastReported: make(map[phase0.Slot]synccommitteemessenger.SlotData)}
}

// Prepare prepares in advance of a sync committee message.
func (*Service) Prepare(_ context.Context, _ interface{}) error {
	return nil
}

// Message generates and broadcasts sync committee messages for a slot.
// It returns a list of messages made.
func (*Service) Message(_ context.Context, _ interface{}) ([]*altair.SyncCommitteeMessage, error) {
	return make([]*altair.SyncCommitteeMessage, 0), nil
}

// GetDataUsedForSlot is a mock.
func (s *Service) GetDataUsedForSlot(slot phase0.Slot) (synccommitteemessenger.SlotData, bool) {
	root, found := s.lastReported[slot]
	return root, found
}

// RemoveHistoricDataUsedForSlotValidation is a mock.
func (*Service) RemoveHistoricDataUsedForSlotVerification(_ phase0.Slot) {}

// PrimeLastReported is used to prime the mock.
func (s *Service) PrimeLastReported(slot phase0.Slot, lastReported synccommitteemessenger.SlotData) {
	s.lastReported[slot] = lastReported
}

// ResetMock is used to reset the mock.
func (s *Service) ResetMock() {
	s.lastReported = make(map[phase0.Slot]synccommitteemessenger.SlotData)
}
