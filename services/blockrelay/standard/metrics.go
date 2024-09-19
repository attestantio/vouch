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
	"math/big"
	"time"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	builderBidCounter                *prometheus.CounterVec
	builderBidTimer                  prometheus.Histogram
	builderBidDeltas                 *prometheus.HistogramVec
	executionConfigCounter           *prometheus.CounterVec
	executionConfigTimer             prometheus.Histogram
	validatorRegistrationsCounter    *prometheus.CounterVec
	validatorRegistrationsGeneration *prometheus.CounterVec
	validatorRegistrationsTimer      prometheus.Histogram
)

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
	if validatorRegistrationsTimer != nil {
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
	executionConfigCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "relay_execution_config",
		Name:      "total",
		Help:      "The number of execution configuration operations",
	}, []string{"result"})
	if err := prometheus.Register(executionConfigCounter); err != nil {
		return err
	}
	executionConfigCounter.WithLabelValues("succeeded").Add(0)
	executionConfigCounter.WithLabelValues("failed").Add(0)

	executionConfigTimer = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "relay_execution_config",
		Name:      "duration_seconds",
		Help:      "The time vouch spends in the execution config operation.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.0,
			3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0,
		},
	})
	if err := prometheus.Register(executionConfigTimer); err != nil {
		return err
	}

	builderBidCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "relay_builder_bid",
		Name:      "total",
		Help:      "The number of builder bid operations",
	}, []string{"result"})
	if err := prometheus.Register(builderBidCounter); err != nil {
		return err
	}
	builderBidCounter.WithLabelValues("succeeded").Add(0)
	builderBidCounter.WithLabelValues("failed").Add(0)

	builderBidTimer = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "relay_builder_bid",
		Name:      "duration_seconds",
		Help:      "The time vouch spends in the builder bid operation.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.0,
			3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0,
		},
	})
	if err := prometheus.Register(builderBidTimer); err != nil {
		return err
	}

	builderBidDeltas = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "relay_builder_bid",
		Name:      "delta_meth",
		Help:      "The amount short the provider was compared to the winning bid (in mETH).",
		Buckets:   prometheus.LinearBuckets(0, 10, 101),
	}, []string{"provider"})
	if err := prometheus.Register(builderBidDeltas); err != nil {
		return err
	}

	validatorRegistrationsTimer = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "relay_validator_registrations",
		Name:      "duration_seconds",
		Help:      "The time vouch spends in the validator registrations operation.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.0,
			3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0,
		},
	})
	if err := prometheus.Register(validatorRegistrationsTimer); err != nil {
		return err
	}

	validatorRegistrationsGeneration = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "relay_validator_registrations",
		Name:      "generation",
		Help:      "The generation of validator registration.",
	}, []string{"source"})
	if err := prometheus.Register(validatorRegistrationsGeneration); err != nil {
		return err
	}

	validatorRegistrationsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "relay_validator_registrations",
		Name:      "total",
		Help:      "The number of execution validator registration operations",
	}, []string{"result"})
	if err := prometheus.Register(validatorRegistrationsCounter); err != nil {
		return err
	}
	validatorRegistrationsCounter.WithLabelValues("succeeded").Add(0)
	validatorRegistrationsCounter.WithLabelValues("failed").Add(0)

	return nil
}

// monitorBuilderBid provides metrics for a builder bid operation.
func monitorBuilderBid(duration time.Duration, succeeded bool) {
	if builderBidTimer == nil {
		// Not yet registered.
		return
	}

	builderBidTimer.Observe(duration.Seconds())
	if succeeded {
		builderBidCounter.WithLabelValues("succeeded").Add(1)
	} else {
		builderBidCounter.WithLabelValues("failed").Add(1)
	}
}

// monitorExecutionConfig provides metrics for an execution config operation.
func monitorExecutionConfig(duration time.Duration, succeeded bool) {
	if executionConfigTimer == nil {
		// Not yet registered.
		return
	}

	executionConfigTimer.Observe(duration.Seconds())
	if succeeded {
		executionConfigCounter.WithLabelValues("succeeded").Add(1)
	} else {
		executionConfigCounter.WithLabelValues("failed").Add(1)
	}
}

// monitorValidatorRegistrations provides metrics for a validator registrations operation.
func monitorValidatorRegistrations(succeeded bool, duration time.Duration) {
	if validatorRegistrationsTimer == nil {
		// Not yet registered.
		return
	}

	validatorRegistrationsTimer.Observe(duration.Seconds())
	if succeeded {
		validatorRegistrationsCounter.WithLabelValues("succeeded").Add(1)
	}
}

// monitorRegistrationsGeneration provides generation metrics for registrations.
func monitorRegistrationsGeneration(source string) {
	if validatorRegistrationsGeneration == nil {
		return
	}
	validatorRegistrationsGeneration.WithLabelValues(source).Inc()
}

// monitorBuilderBidDelta provides builder bid deltas for blocks.
func monitorBuilderBidDelta(source string, delta *big.Int) {
	if builderBidDeltas == nil {
		return
	}
	builderBidDeltas.WithLabelValues(source).Observe(float64(delta.Uint64()) / 1e15)
}
