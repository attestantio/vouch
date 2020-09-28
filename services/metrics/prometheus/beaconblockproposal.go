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

func (s *Service) setupBeaconBlockProposalMetrics() error {
	s.beaconBlockProposalProcessTimer =
		prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "vouch",
			Subsystem: "beaconblockproposal_process",
			Name:      "duration_seconds",
			Help:      "The time vouch spends from starting the beacon block proposal process to submitting the beacon block.",
			Buckets: []float64{
				0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
				1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			},
		})
	if err := prometheus.Register(s.beaconBlockProposalProcessTimer); err != nil {
		return err
	}

	s.beaconBlockProposalProcessRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "beaconblockproposal_process",
		Name:      "requests_total",
		Help:      "The number of beacon block proposal processes.",
	}, []string{"result"})
	if err := prometheus.Register(s.beaconBlockProposalProcessRequests); err != nil {
		return err
	}

	return nil
}

// BeaconBlockProposalCompleted is called when a block proposal process has completed.
func (s *Service) BeaconBlockProposalCompleted(started time.Time, result string) {
	s.beaconBlockProposalProcessTimer.Observe(time.Since(started).Seconds())
	s.beaconBlockProposalProcessRequests.WithLabelValues(result).Inc()
}
