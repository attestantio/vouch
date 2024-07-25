// Copyright © 2021 - 2024 Attestant Limited.
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

package prometheus

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

func (s *Service) setupSyncCommitteeValidationMetrics() error {
	s.syncCommitteeValidationHeadMismatches = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteevalidation",
		Name:      "mismatches_total",
		Help:      "The number of sync committee messages we broadcast that did not match the next head root.",
	}, []string{"slot", "head_parent_root", "broadcast_root"})
	if err := prometheus.Register(s.syncCommitteeValidationHeadMismatches); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.syncCommitteeValidationHeadMismatches = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	s.syncCommitteeValidationGetHeadFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteevalidation",
		Name:      "get_head_failures_total",
		Help:      "The number of times sync committee validation failed due to being unable to retrieve the head block.",
	}, []string{"slot", "block"})
	if err := prometheus.Register(s.syncCommitteeValidationGetHeadFailures); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.syncCommitteeValidationGetHeadFailures = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	s.syncCommitteeValidationAggregateFound = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteevalidation",
		Name:      "found_total",
		Help:      "The number of sync committee messages that were included in the sync aggregate.",
	}, []string{"slot"})
	if err := prometheus.Register(s.syncCommitteeValidationAggregateFound); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.syncCommitteeValidationAggregateFound = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	s.syncCommitteeValidationAggregateMissing = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteevalidation",
		Name:      "missing_total",
		Help:      "The number of sync committee messages that were not included in the sync aggregate.",
	}, []string{"slot"})
	if err := prometheus.Register(s.syncCommitteeValidationAggregateMissing); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.syncCommitteeValidationAggregateMissing = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	return nil
}

// SyncCommitteeSyncAggregateFoundInc is called when our sync committee participation was included in the SyncAggregate for the next head.
func (s *Service) SyncCommitteeSyncAggregateFoundInc() {
	s.syncCommitteeValidationAggregateFound.WithLabelValues("").Add(1)
}

// SyncCommitteeSyncAggregateMissingInc is called when our sync committee participation was not included in the SyncAggregate for the next head.
func (s *Service) SyncCommitteeSyncAggregateMissingInc() {
	s.syncCommitteeValidationAggregateMissing.WithLabelValues("").Add(1)
}

// SyncCommitteeGetHeadBlockFailedInc is called when validation for a sync committee fails due to being unable to retrieve the head block.
func (s *Service) SyncCommitteeGetHeadBlockFailedInc() {
	s.syncCommitteeValidationGetHeadFailures.WithLabelValues("").Add(1)
}

// SyncCommitteeMessagesHeadMismatchInc is called when a sync committee message was known to not match the next head block.
func (s *Service) SyncCommitteeMessagesHeadMismatchInc() {
	s.syncCommitteeValidationHeadMismatches.WithLabelValues("").Add(1)
}
