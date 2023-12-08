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

package prometheus

import (
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (s *Service) setupBeaconCommitteeSubscriptionMetrics() error {
	s.beaconCommitteeSubscriptionProcessTimer = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "beaconcommitteesubscription_process",
		Name:      "duration_seconds",
		Help:      "The time vouch spends from starting the beacon committee subscription process to submitting the subscription request.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
		},
	})
	if err := prometheus.Register(s.beaconCommitteeSubscriptionProcessTimer); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.beaconCommitteeSubscriptionProcessTimer = alreadyRegisteredError.ExistingCollector.(prometheus.Histogram)
		} else {
			return err
		}
	}

	s.beaconCommitteeSubscriptionProcessRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "beaconcommitteesubscription_process",
		Name:      "requests_total",
		Help:      "The number of beacon committee subscription processes.",
	}, []string{"result"})
	if err := prometheus.Register(s.beaconCommitteeSubscriptionProcessRequests); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.beaconCommitteeSubscriptionProcessRequests = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	s.beaconCommitteeSubscribers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "beaconcommitteesubscription",
		Name:      "subscribers_total",
		Help:      "The number of beacon committee subscribed.",
	})
	if err := prometheus.Register(s.beaconCommitteeSubscribers); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.beaconCommitteeSubscribers = alreadyRegisteredError.ExistingCollector.(prometheus.Gauge)
		} else {
			return err
		}
	}

	s.beaconCommitteeAggregators = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "beaconcommitteesubscription",
		Name:      "aggregators_total",
		Help:      "The number of beacon committee aggregated.",
	})
	if err := prometheus.Register(s.beaconCommitteeAggregators); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.beaconCommitteeAggregators = alreadyRegisteredError.ExistingCollector.(prometheus.Gauge)
		} else {
			return err
		}
	}

	return nil
}

// BeaconCommitteeSubscriptionCompleted is called when an beacon committee subscription process has completed.
func (s *Service) BeaconCommitteeSubscriptionCompleted(started time.Time, result string) {
	// Only log times for successful completions.
	if result == "succeeded" {
		s.beaconCommitteeSubscriptionProcessTimer.Observe(time.Since(started).Seconds())
	}
	s.beaconCommitteeSubscriptionProcessRequests.WithLabelValues(result).Inc()
}

// BeaconCommitteeSubscribers sets the number of beacon committees to which our validators are subscribed.
func (s *Service) BeaconCommitteeSubscribers(subscribers int) {
	s.beaconCommitteeSubscribers.Set(float64(subscribers))
}

// BeaconCommitteeAggregators sets the number of beacon committees for which our validators are aggregating.
func (s *Service) BeaconCommitteeAggregators(aggregators int) {
	s.beaconCommitteeAggregators.Set(float64(aggregators))
}
