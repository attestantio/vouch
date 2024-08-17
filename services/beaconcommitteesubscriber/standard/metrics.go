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
	beaconCommitteeSubscriptionProcessTimer    prometheus.Histogram
	beaconCommitteeSubscriptionProcessRequests *prometheus.CounterVec
	beaconCommitteeSubscribers                 prometheus.Gauge
	beaconCommitteeAggregators                 prometheus.Gauge
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
	beaconCommitteeSubscriptionProcessTimer = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "beaconcommitteesubscription_process",
		Name:      "duration_seconds",
		Help:      "The time vouch spends from starting the beacon committee subscription process to submitting the subscription request.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
		},
	})
	if err := prometheus.Register(beaconCommitteeSubscriptionProcessTimer); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			beaconCommitteeSubscriptionProcessTimer = alreadyRegisteredError.ExistingCollector.(prometheus.Histogram)
		} else {
			return err
		}
	}

	beaconCommitteeSubscriptionProcessRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "beaconcommitteesubscription_process",
		Name:      "requests_total",
		Help:      "The number of beacon committee subscription processes.",
	}, []string{"result"})
	if err := prometheus.Register(beaconCommitteeSubscriptionProcessRequests); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			beaconCommitteeSubscriptionProcessRequests = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	beaconCommitteeSubscribers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "beaconcommitteesubscription",
		Name:      "subscribers_total",
		Help:      "The number of beacon committee subscribed.",
	})
	if err := prometheus.Register(beaconCommitteeSubscribers); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			beaconCommitteeSubscribers = alreadyRegisteredError.ExistingCollector.(prometheus.Gauge)
		} else {
			return err
		}
	}

	beaconCommitteeAggregators = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "beaconcommitteesubscription",
		Name:      "aggregators_total",
		Help:      "The number of beacon committee aggregated.",
	})
	if err := prometheus.Register(beaconCommitteeAggregators); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			beaconCommitteeAggregators = alreadyRegisteredError.ExistingCollector.(prometheus.Gauge)
		} else {
			return err
		}
	}

	return nil
}

func monitorBeaconCommitteeSubscriptionCompleted(started time.Time, result string) {
	if beaconCommitteeSubscriptionProcessTimer == nil || beaconCommitteeSubscriptionProcessRequests == nil {
		return
	}
	// Only log times for successful completions.
	if result == "succeeded" {
		beaconCommitteeSubscriptionProcessTimer.Observe(time.Since(started).Seconds())
	}
	beaconCommitteeSubscriptionProcessRequests.WithLabelValues(result).Inc()
}

func monitorBeaconCommitteeSubscribers(subscribers int) {
	if beaconCommitteeSubscribers == nil {
		return
	}
	beaconCommitteeSubscribers.Set(float64(subscribers))
}

func monitorBeaconCommitteeAggregators(aggregators int) {
	if beaconCommitteeAggregators == nil {
		return
	}
	beaconCommitteeAggregators.Set(float64(aggregators))
}
