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

	"github.com/attestantio/vouch/services/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var auctionBlockCounter *prometheus.CounterVec
var auctionBlockTimer prometheus.Histogram
var boostConfigCounter *prometheus.CounterVec
var boostConfigTimer prometheus.Histogram
var builderBidCounter *prometheus.CounterVec
var builderBidTimer prometheus.Histogram
var validatorRegistrationsCounter *prometheus.CounterVec
var validatorRegistrationsTimer prometheus.Histogram

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
	auctionBlockCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "relay_auction_block",
		Name:      "used_total",
		Help:      "The auction block provider used by a relay.",
	}, []string{"provider", "result"})
	if err := prometheus.Register(auctionBlockCounter); err != nil {
		return err
	}

	auctionBlockTimer = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "relay_auction_block",
		Name:      "duration_seconds",
		Help:      "The time vouch spends in the auction block operation.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.0,
			3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0,
		},
	})
	if err := prometheus.Register(auctionBlockTimer); err != nil {
		return err
	}

	boostConfigCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "relay_boost_config",
		Name:      "total",
		Help:      "The number of boost configuration operations",
	}, []string{"result"})
	if err := prometheus.Register(boostConfigCounter); err != nil {
		return err
	}
	boostConfigCounter.WithLabelValues("succeeded").Add(0)
	boostConfigCounter.WithLabelValues("failed").Add(0)

	boostConfigTimer = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "relay_boost_config",
		Name:      "duration_seconds",
		Help:      "The time vouch spends in the boost config operation.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.0,
			3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0,
		},
	})
	if err := prometheus.Register(boostConfigTimer); err != nil {
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

	validatorRegistrationsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "relay_validator_registrations",
		Name:      "total",
		Help:      "The number of boost validator registration operations",
	}, []string{"result"})
	if err := prometheus.Register(validatorRegistrationsCounter); err != nil {
		return err
	}
	validatorRegistrationsCounter.WithLabelValues("succeeded").Add(0)
	validatorRegistrationsCounter.WithLabelValues("failed").Add(0)

	return nil
}

// monitorAuctionBlock provides metrics for an auction block operation.
func monitorAuctionBlock(provider string, succeeded bool, duration time.Duration) {
	if auctionBlockCounter == nil {
		// Not yet registered.
		return
	}

	auctionBlockTimer.Observe(duration.Seconds())
	if succeeded {
		auctionBlockCounter.WithLabelValues(provider, "succeeded").Add(1)
	}
}

// monitorBoostConfig provides metrics for a boost config operation.
func monitorBoostConfig(duration time.Duration, succeeded bool) {
	if boostConfigTimer == nil {
		// Not yet registered.
		return
	}

	boostConfigTimer.Observe(duration.Seconds())
	if succeeded {
		boostConfigCounter.WithLabelValues("succeeded").Add(1)
	} else {
		boostConfigCounter.WithLabelValues("failed").Add(1)
	}
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