// Copyright © 2024 Attestant Limited.
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

package standard

import (
	"context"
	"errors"
	"time"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	syncCommitteeSubscriptionProcessTimer    prometheus.Histogram
	syncCommitteeSubscriptionProcessRequests *prometheus.CounterVec
	syncCommitteeSubscribers                 prometheus.Gauge
)

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
	if monitor == nil {
		// No monitor.
		return nil
	}
	if monitor.Presenter() == "prometheus" {
		return registerPrometheusMetrics(ctx)
	}
	return nil
}

func registerPrometheusMetrics(_ context.Context) error {
	syncCommitteeSubscriptionProcessTimer = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteesubscription_process",
		Name:      "duration_seconds",
		Help:      "The time vouch spends from starting the sync committee subscription process to submitting the subscription request.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
		},
	})
	if err := prometheus.Register(syncCommitteeSubscriptionProcessTimer); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			syncCommitteeSubscriptionProcessTimer = alreadyRegisteredError.ExistingCollector.(prometheus.Histogram)
		} else {
			return err
		}
	}

	syncCommitteeSubscriptionProcessRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteesubscription_process",
		Name:      "requests_total",
		Help:      "The number of sync committee subscription processes.",
	}, []string{"result"})
	if err := prometheus.Register(syncCommitteeSubscriptionProcessRequests); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			syncCommitteeSubscriptionProcessRequests = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	syncCommitteeSubscribers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteesubscription",
		Name:      "subscribers_total",
		Help:      "The number of sync committee subscribed.",
	})
	if err := prometheus.Register(syncCommitteeSubscribers); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			syncCommitteeSubscribers = alreadyRegisteredError.ExistingCollector.(prometheus.Gauge)
		} else {
			return err
		}
	}

	return nil
}

func monitorSyncCommitteeSubscriptionCompleted(started time.Time, result string) {
	if syncCommitteeSubscriptionProcessTimer == nil || syncCommitteeSubscriptionProcessRequests == nil {
		return
	}
	// Only log times for successful completions.
	if result == "succeeded" {
		syncCommitteeSubscriptionProcessTimer.Observe(time.Since(started).Seconds())
	}
	syncCommitteeSubscriptionProcessRequests.WithLabelValues(result).Inc()
}

func monitorSyncCommitteeSubscribers(subscribers int) {
	if syncCommitteeSubscribers == nil {
		return
	}
	syncCommitteeSubscribers.Set(float64(subscribers))
}
