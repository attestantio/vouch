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

package prometheus

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (s *Service) setupSyncCommitteeAggregationMetrics() error {
	s.syncCommitteeAggregationProcessTimer =
		prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "vouch",
			Subsystem: "sync_committee_aggregation_process",
			Name:      "duration_seconds",
			Help:      "The time vouch spends from starting the sync committee aggregation process to submitting the sync committee aggregations.",
			Buckets: []float64{
				0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
				1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			},
		})
	if err := prometheus.Register(s.syncCommitteeAggregationProcessTimer); err != nil {
		return err
	}

	s.syncCommitteeAggregationProcessRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "sync_committee_aggregation_process",
		Name:      "requests_total",
		Help:      "The number of sync committee aggregation processes.",
	}, []string{"result"})
	if err := prometheus.Register(s.syncCommitteeAggregationProcessRequests); err != nil {
		return err
	}

	s.syncCommitteeAggregationCoverageRatio =
		prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "vouch",
			Subsystem: "sync_committee_aggregation",
			Name:      "coverage_ratio",
			Help:      "The ratio of included to possible messages in the aggregate.",
			Buckets:   []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
		})
	return prometheus.Register(s.syncCommitteeAggregationCoverageRatio)
}

// SyncCommitteeAggregationsCompleted is called when a sync committee aggregation process has completed.
func (s *Service) SyncCommitteeAggregationsCompleted(started time.Time, count int, result string) {
	// Only log times for successful completions.
	if result == "succeeded" {
		duration := time.Since(started).Seconds()
		for i := 0; i < count; i++ {
			s.syncCommitteeAggregationProcessTimer.Observe(duration)
		}
	}
	s.syncCommitteeAggregationProcessRequests.WithLabelValues(result).Add(float64(count))
}

// SyncCommitteeAggregationCoverage measures the message ratio of the sync committee aggregation.
func (s *Service) SyncCommitteeAggregationCoverage(frac float64) {
	s.syncCommitteeAggregationCoverageRatio.Observe(frac)
}
