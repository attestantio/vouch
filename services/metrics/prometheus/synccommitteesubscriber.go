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
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (s *Service) setupSyncCommitteeSubscriptionMetrics() error {
	s.syncCommitteeSubscriptionProcessTimer = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteesubscription_process",
		Name:      "duration_seconds",
		Help:      "The time vouch spends from starting the sync committee subscription process to submitting the subscription request.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
		},
	})
	if err := prometheus.Register(s.syncCommitteeSubscriptionProcessTimer); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.syncCommitteeSubscriptionProcessTimer = alreadyRegisteredError.ExistingCollector.(prometheus.Histogram)
		} else {
			return err
		}
	}

	s.syncCommitteeSubscriptionProcessRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteesubscription_process",
		Name:      "requests_total",
		Help:      "The number of sync committee subscription processes.",
	}, []string{"result"})
	if err := prometheus.Register(s.syncCommitteeSubscriptionProcessRequests); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.syncCommitteeSubscriptionProcessRequests = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	s.syncCommitteeSubscribers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteesubscription",
		Name:      "subscribers_total",
		Help:      "The number of sync committee subscribed.",
	})
	if err := prometheus.Register(s.syncCommitteeSubscribers); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			s.syncCommitteeSubscribers = alreadyRegisteredError.ExistingCollector.(prometheus.Gauge)
		} else {
			return err
		}
	}

	return nil
}

// SyncCommitteeSubscriptionCompleted is called when an sync committee subscription process has completed.
func (s *Service) SyncCommitteeSubscriptionCompleted(started time.Time, result string) {
	// Only log times for successful completions.
	if result == "succeeded" {
		s.syncCommitteeSubscriptionProcessTimer.Observe(time.Since(started).Seconds())
	}
	s.syncCommitteeSubscriptionProcessRequests.WithLabelValues(result).Inc()
}

// SyncCommitteeSubscribers sets the number of sync committees to which our validators are subscribed.
func (s *Service) SyncCommitteeSubscribers(subscribers int) {
	s.syncCommitteeSubscribers.Set(float64(subscribers))
}
