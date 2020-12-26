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

// Package metrics tracks various metrics that measure the performance of vouch.
package metrics

import "time"

// Service is the generic metrics service.
type Service interface{}

// SchedulerMonitor provides methods to monitor the scheduler service.
type SchedulerMonitor interface {
	// JobScheduled is called when a job is scheduled.
	JobScheduled()
	// JobCancelled is called when a scheduled job is cancelled.
	JobCancelled()
	// JobStartedOnTimer is called when a scheduled job is started due to meeting its time.
	JobStartedOnTimer()
	// JobStartedOnSignal is called when a scheduled job is started due to being manually signal.
	JobStartedOnSignal()
}

// ControllerMonitor provides methods to monitor the controller service.
type ControllerMonitor interface {
	// NewEpoch is called when vouch starts processing a new epoch.
	NewEpoch()
	// BlockDelay provides the delay between the start of a slot and vouch receiving its block.
	BlockDelay(epochSlot uint, delay time.Duration)
}

// BeaconBlockProposalMonitor provides methods to monitor the block proposal process.
type BeaconBlockProposalMonitor interface {
	// BeaconBlockProposalCompleted is called when a block proposal process has completed.
	BeaconBlockProposalCompleted(started time.Time, result string)
}

// AttestationMonitor provides methods to monitor the attestation process.
type AttestationMonitor interface {
	// AttestationsCompleted is called when an attestation process has completed.
	AttestationsCompleted(started time.Time, count int, result string)
}

// AttestationAggregationMonitor provides methods to monitor the attestation aggregation process.
type AttestationAggregationMonitor interface {
	// AttestationAggregationCompleted is called when an attestation aggregation process has completed.
	AttestationAggregationCompleted(started time.Time, result string)

	// AttestationAggregationCoverage measures the attestation ratio of the attestation aggregation.
	AttestationAggregationCoverage(frac float64)
}

// BeaconCommitteeSubscriptionMonitor provides methods to monitor the outcome of beacon committee subscriptions.
type BeaconCommitteeSubscriptionMonitor interface {
	// BeaconCommitteeSubscriptionCompleted is called when an beacon committee subscription process has completed.
	BeaconCommitteeSubscriptionCompleted(started time.Time, result string)
	// BeaconCommitteeSubscribers sets the number of beacon committees to which our validators are subscribed.
	BeaconCommitteeSubscribers(subscribers int)
	// BeaconCommitteeAggregators sets the number of beacon committees for which our validators are aggregating.
	BeaconCommitteeAggregators(aggregators int)
}

// AccountManagerMonitor provides methods to monitor the account manager.
type AccountManagerMonitor interface {
	// Accounts sets the number of accounts in a given state.
	Accounts(state string, count uint64)
}

// ClientMonitor provides methods to monitor client connections.
type ClientMonitor interface {
	// ClientOperation provides a generic monitor for client operations.
	ClientOperation(provider string, name string, succeeded bool, duration time.Duration)
}

// ValidatorsManagerMonitor provides methods to monitor the validators manager.
type ValidatorsManagerMonitor interface {
}

// SignerMonitor provides methods to monitor signers.
type SignerMonitor interface {
}
