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

func (s *Service) setupAttestationAggregationMetrics() error {
	s.attestationAggregationProcessTimer =
		prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "vouch",
			Subsystem: "attestationaggregation_process",
			Name:      "duration_seconds",
			Help:      "The time vouch spends from starting the beacon block attestation aggregation process to submitting the aggregation beacon block attestation.",
			Buckets: []float64{
				0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
				1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			},
		})
	if err := prometheus.Register(s.attestationAggregationProcessTimer); err != nil {
		return err
	}

	s.attestationAggregationProcessRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "attestationaggregation_process",
		Name:      "requests_total",
		Help:      "The number of beacon block attestation aggregation processes.",
	}, []string{"result"})
	if err := prometheus.Register(s.attestationAggregationProcessRequests); err != nil {
		return err
	}

	s.attestationAggregationCoverageRatio =
		prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "vouch",
			Subsystem: "attestationaggregation",
			Name:      "coverage_ratio",
			Help:      "The ratio of included to possible attestations in the aggregate.",
			Buckets:   []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
		})
	return prometheus.Register(s.attestationAggregationCoverageRatio)
}

// AttestationAggregationCompleted is called when an attestation aggregationprocess has completed.
func (s *Service) AttestationAggregationCompleted(started time.Time, result string) {
	s.attestationAggregationProcessTimer.Observe(time.Since(started).Seconds())
	s.attestationAggregationProcessRequests.WithLabelValues(result).Inc()
}

// AttestationAggregationCoverage measures the attestation ratio of the attestation aggregation.
func (s *Service) AttestationAggregationCoverage(frac float64) {
	s.attestationAggregationCoverageRatio.Observe(frac)
}
