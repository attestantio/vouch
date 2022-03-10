// Copyright © 2022 Attestant Limited.
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

package static

import (
	"context"
	"time"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var processTimer prometheus.Histogram
var latestTimestamp prometheus.Gauge
var requestsProcessed *prometheus.CounterVec

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
	if latestTimestamp != nil {
		// Already registered.
		return nil
	}
	if monitor == nil {
		// No monitor.
		return nil
	}
	if monitor.Presenter() == "prometheus" {
		return registerPrometheusMetrics(ctx)
	}
	return nil
}

func registerPrometheusMetrics(ctx context.Context) error {
	processTimer =
		prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "vouch",
			Subsystem: "feerecipient_process",
			Name:      "duration_seconds",
			Help:      "The time vouch spends from starting the fee recipient request to returning the fee recipients.",
			Buckets: []float64{
				0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
				1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			},
		})
	if err := prometheus.Register(processTimer); err != nil {
		return err
	}

	latestTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "feerecipient_process",
		Name:      "latest_timestamp",
		Help:      "The latest timestamp for which Vouch provided fee recipients.",
	})
	if err := prometheus.Register(latestTimestamp); err != nil {
		return err
	}

	requestsProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "feerecipient_process",
		Name:      "requests_total",
		Help:      "The number of fee recipient processes.",
	}, []string{"result"})
	return prometheus.Register(requestsProcessed)
}

// feeRecipientsCompleted is called when a fee recipient process has completed.
func feeRecipientsCompleted(started time.Time, result string) {
	if latestTimestamp == nil {
		return
	}

	// Only log times for successful completions.
	if result == "succeeded" {
		processTimer.Observe(time.Since(started).Seconds())
		latestTimestamp.SetToCurrentTime()
	}
}
