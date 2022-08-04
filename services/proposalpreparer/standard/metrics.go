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

package standard

import (
	"context"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var processTimer prometheus.Histogram
var latestEpoch prometheus.Gauge
var requestsProcessed *prometheus.CounterVec
var registrationsProcessed *prometheus.CounterVec

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
	if latestEpoch != nil {
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

func registerPrometheusMetrics(_ context.Context) error {
	processTimer =
		prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "vouch",
			Subsystem: "proposalpreparation_process",
			Name:      "duration_seconds",
			Help:      "The time vouch spends from starting the proposal preparation process to submitting the proposal preparations.",
			Buckets: []float64{
				0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
				1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			},
		})
	if err := prometheus.Register(processTimer); err != nil {
		return err
	}

	latestEpoch = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "proposalpreparation_process",
		Name:      "latest_epoch",
		Help:      "The latest epoch for which Vouch presented proposal preparations.",
	})
	if err := prometheus.Register(latestEpoch); err != nil {
		return err
	}

	requestsProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "proposalpreparation_process",
		Name:      "requests_total",
		Help:      "The number of proposal preparation processes.",
	}, []string{"result"})
	if err := prometheus.Register(requestsProcessed); err != nil {
		return err
	}

	registrationsProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "validatorregistrations",
		Name:      "requests_total",
		Help:      "The number of validator registration processes.",
	}, []string{"result"})
	return prometheus.Register(registrationsProcessed)
}

// proposalPreparationCompleted is called when a proposal preparation process has completed.
func proposalPreparationCompleted(started time.Time, epoch phase0.Epoch, result string) {
	if latestEpoch == nil {
		return
	}

	requestsProcessed.WithLabelValues(result).Inc()
	// Only log times for successful completions.
	if result == "succeeded" {
		processTimer.Observe(time.Since(started).Seconds())
		latestEpoch.Set(float64(epoch))
	}
}

// validatorRegistrationsCompleted is called when a validator registration process has completed.
func validatorRegistrationsCompleted(result string) {
	if registrationsProcessed == nil {
		return
	}

	registrationsProcessed.WithLabelValues(result).Inc()
}
