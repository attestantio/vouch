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

var validatorRegistrationsTimer prometheus.Histogram
var auctionBlockCounter *prometheus.CounterVec
var auctionBlockTimer prometheus.Histogram

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
	return prometheus.Register(auctionBlockTimer)
}

// monitorValidatorRegistrations provides metrics for a validator registrations operation.
func monitorValidatorRegistrations(duration time.Duration) {
	if validatorRegistrationsTimer == nil {
		// Not yet registered.
		return
	}

	validatorRegistrationsTimer.Observe(duration.Seconds())
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
