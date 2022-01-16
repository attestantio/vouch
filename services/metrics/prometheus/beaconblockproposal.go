// Copyright © 2020 - 2022 Attestant Limited.
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

	"github.com/attestantio/go-eth2-client/spec/phase0"
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

	s.beaconBlockProposalMarkTimer =
		prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "vouch",
			Subsystem: "beaconblockproposal",
			Name:      "mark_seconds",
			Help:      "The time in to the slot at which the beacon block was broadcast.",
			Buckets: []float64{
				0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
				1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
				2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.0,
				3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0,
				4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 5.0,
				5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 6.0,
				6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9, 7.0,
				7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9, 8.0,
				8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 9.0,
				9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9, 10.0,
				10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9, 11.0,
				11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8, 11.9, 12.0,
			},
		})
	if err := prometheus.Register(s.beaconBlockProposalMarkTimer); err != nil {
		return err
	}

	s.beaconBlockProposalProcessLatestSlot = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "beaconblockproposal_process",
		Name:      "latest_slot",
		Help:      "The latest slot for which Vouch proposed.",
	})
	if err := prometheus.Register(s.beaconBlockProposalProcessLatestSlot); err != nil {
		return err
	}

	s.beaconBlockProposalProcessRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "beaconblockproposal_process",
		Name:      "requests_total",
		Help:      "The number of beacon block proposal processes.",
	}, []string{"result"})
	return prometheus.Register(s.beaconBlockProposalProcessRequests)
}

// BeaconBlockProposalCompleted is called when a block proposal process has completed.
func (s *Service) BeaconBlockProposalCompleted(started time.Time, slot phase0.Slot, result string) {
	// Only log times for successful completions.
	if result == "succeeded" {
		s.beaconBlockProposalProcessTimer.Observe(time.Since(started).Seconds())
		secsSinceStartOfSlot := time.Since(s.chainTime.StartOfSlot(slot)).Seconds()
		s.beaconBlockProposalMarkTimer.Observe(secsSinceStartOfSlot)
		s.beaconBlockProposalProcessLatestSlot.Set(float64(slot))
	}
	s.beaconBlockProposalProcessRequests.WithLabelValues(result).Inc()
}
