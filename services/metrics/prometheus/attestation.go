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

func (s *Service) setupAttestationMetrics() error {
	s.attestationProcessTimer =
		prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "vouch",
			Subsystem: "attestation_process",
			Name:      "duration_seconds",
			Help:      "The time vouch spends from starting the attestation process to submitting the attestation.",
			Buckets: []float64{
				0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
				1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			},
		})
	if err := prometheus.Register(s.attestationProcessTimer); err != nil {
		return err
	}

	s.attestationProcessRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "attestation_process",
		Name:      "requests_total",
		Help:      "The number of attestation processes.",
	}, []string{"result"})
	return prometheus.Register(s.attestationProcessRequests)
}

// AttestationsCompleted is called when an attestation process has completed.
func (s *Service) AttestationsCompleted(started time.Time, count int, result string) {
	duration := time.Since(started).Seconds()
	for i := 0; i < count; i++ {
		s.attestationProcessTimer.Observe(duration)
	}
	s.attestationProcessRequests.WithLabelValues(result).Add(float64(count))
}
