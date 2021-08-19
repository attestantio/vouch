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

package prometheus

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (s *Service) setupSyncCommitteeMessageMetrics() error {
	s.syncCommitteeMessageProcessTimer =
		prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "vouch",
			Subsystem: "sync_committee_message_process",
			Name:      "duration_seconds",
			Help:      "The time vouch spends from starting the sync committee message process to submitting the sync committee messages.",
			Buckets: []float64{
				0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
				1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			},
		})
	if err := prometheus.Register(s.syncCommitteeMessageProcessTimer); err != nil {
		return err
	}

	s.syncCommitteeMessageProcessRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "sync_committee_message_process",
		Name:      "requests_total",
		Help:      "The number of sync committee message processes.",
	}, []string{"result"})
	return prometheus.Register(s.syncCommitteeMessageProcessRequests)
}

// SyncCommitteeMessagesCompleted is called when a sync committee message process has completed.
func (s *Service) SyncCommitteeMessagesCompleted(started time.Time, count int, result string) {
	duration := time.Since(started).Seconds()
	for i := 0; i < count; i++ {
		s.syncCommitteeMessageProcessTimer.Observe(duration)
	}
	s.syncCommitteeMessageProcessRequests.WithLabelValues(result).Add(float64(count))
}
