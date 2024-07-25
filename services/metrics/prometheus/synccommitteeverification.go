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

func (s *Service) setupSyncCommitteeVerificationMetrics() error {
	s.syncCommitteeVerificationHeadMismatches = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteeverification",
		Name:      "mismatches_total",
		Help:      "The number of sync committee messages we broadcast that did not match the next head root.",
	}, []string{})
	if err := prometheus.Register(s.syncCommitteeVerificationHeadMismatches); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.syncCommitteeVerificationHeadMismatches = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	s.syncCommitteeVerificationGetHeadFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteeverification",
		Name:      "get_head_failures_total",
		Help:      "The number of times sync committee verification failed due to being unable to retrieve the head block.",
	}, []string{})
	if err := prometheus.Register(s.syncCommitteeVerificationGetHeadFailures); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.syncCommitteeVerificationGetHeadFailures = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	s.syncCommitteeVerificationAggregateFound = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteeverification",
		Name:      "found_total",
		Help:      "The number of sync committee messages that were included in the sync aggregate.",
	}, []string{})
	if err := prometheus.Register(s.syncCommitteeVerificationAggregateFound); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.syncCommitteeVerificationAggregateFound = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	s.syncCommitteeVerificationAggregateMissing = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteeverification",
		Name:      "missing_total",
		Help:      "The number of sync committee messages that were not included in the sync aggregate.",
	}, []string{})
	if err := prometheus.Register(s.syncCommitteeVerificationAggregateMissing); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.syncCommitteeVerificationAggregateMissing = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	return nil
}

// SyncCommitteeSyncAggregateFoundInc is called when our sync committee participation was included in the SyncAggregate for the next head.
func (s *Service) SyncCommitteeSyncAggregateFoundInc() {
	s.syncCommitteeVerificationAggregateFound.WithLabelValues().Add(1)
}

// SyncCommitteeSyncAggregateMissingInc is called when our sync committee participation was not included in the SyncAggregate for the next head.
func (s *Service) SyncCommitteeSyncAggregateMissingInc() {
	s.syncCommitteeVerificationAggregateMissing.WithLabelValues().Add(1)
}

// SyncCommitteeGetHeadBlockFailedInc is called when verification for a sync committee fails due to being unable to retrieve the head block.
func (s *Service) SyncCommitteeGetHeadBlockFailedInc() {
	s.syncCommitteeVerificationGetHeadFailures.WithLabelValues().Add(1)
}

// SyncCommitteeMessagesHeadMismatchInc is called when a sync committee message was known to not match the next head block.
func (s *Service) SyncCommitteeMessagesHeadMismatchInc() {
	s.syncCommitteeVerificationHeadMismatches.WithLabelValues().Add(1)
}
