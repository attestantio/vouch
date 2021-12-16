// Copyright © 2020, 2021 Attestant Limited.
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

// Package null is a null metrics logger.
package null

import (
	"context"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// Service is a metrics service that drops metrics.
type Service struct{}

// New creates a new null metrics service.
func New(_ context.Context) *Service {
	return &Service{}
}

// Presenter provides the presenter for this service.
func (s *Service) Presenter() string {
	return "null"
}

// JobScheduled is called when a job is scheduled.
func (s *Service) JobScheduled(_ string) {}

// JobCancelled is called when a scheduled job is cancelled.
func (s *Service) JobCancelled(_ string) {}

// JobStartedOnTimer is called when a scheduled job is started due to meeting its time.
func (s *Service) JobStartedOnTimer(_ string) {}

// JobStartedOnSignal is called when a scheduled job is started due to being manually signal.
func (s *Service) JobStartedOnSignal(_ string) {}

// NewEpoch is called when vouch starts processing a new epoch.
func (s *Service) NewEpoch() {}

// BlockDelay provides the delay between the start of a slot and vouch receiving its block.
func (s *Service) BlockDelay(_ uint, _ time.Duration) {}

// BeaconBlockProposalCompleted is called when a block proposal process has completed.
func (s *Service) BeaconBlockProposalCompleted(_ time.Time, _ phase0.Slot, _ string) {}

// AttestationsCompleted is called when an attestation process has completed.
func (s *Service) AttestationsCompleted(_ time.Time, _ phase0.Slot, _ int, _ string) {
}

// AttestationAggregationCompleted is called when an attestation aggregation process has completed.
func (s *Service) AttestationAggregationCompleted(_ time.Time, _ phase0.Slot, _ string) {
}

// AttestationAggregationCoverage measures the attestation ratio of the attestation aggregation.
func (s *Service) AttestationAggregationCoverage(_ float64) {}

// BeaconCommitteeSubscriptionCompleted is called when an beacon committee subscription process has completed.
func (s *Service) BeaconCommitteeSubscriptionCompleted(_ time.Time, _ string) {}

// BeaconCommitteeSubscribers sets the number of beacon committees to which our validators are subscribed.
func (s *Service) BeaconCommitteeSubscribers(_ int) {}

// BeaconCommitteeAggregators sets the number of beacon committees for which our validators are aggregating.
func (s *Service) BeaconCommitteeAggregators(_ int) {}

// Accounts sets the number of accounts in a given state.
func (s *Service) Accounts(_ string, _ uint64) {}

// ClientOperation provides a generic monitor for client operations.
func (s *Service) ClientOperation(_ string, _ string, _ bool, _ time.Duration) {
}

// StrategyOperation provides a generic monitor for strategy operations.
func (s *Service) StrategyOperation(_ string, _ string, _ string, _ time.Duration) {
}

// SyncCommitteeAggregationsCompleted is called when a sync committee aggregation process has completed.
func (s *Service) SyncCommitteeAggregationsCompleted(_ time.Time, _ phase0.Slot, _ int, _ string) {
}

// SyncCommitteeAggregationCoverage measures the message ratio of the sync committee aggregation.
func (s *Service) SyncCommitteeAggregationCoverage(_ float64) {
}

// SyncCommitteeMessagesCompleted is called when a sync committee message process has completed.
func (s *Service) SyncCommitteeMessagesCompleted(_ time.Time, _ phase0.Slot, _ int, _ string) {
}

// SyncCommitteeSubscriptionCompleted is called when a sync committee subscription process has completed.
func (s *Service) SyncCommitteeSubscriptionCompleted(_ time.Time, _ string) {
}

// SyncCommitteeSubscribers sets the number of sync committees to which our validators are subscribed.
func (s *Service) SyncCommitteeSubscribers(_ int) {
}
