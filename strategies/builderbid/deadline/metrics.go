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

package deadline

import (
	"context"
	"math/big"
	"time"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	auctionBlockUsed  *prometheus.CounterVec
	auctionBlockTimer prometheus.Histogram
	bidDelta          *prometheus.HistogramVec
	bidPctDelta       *prometheus.HistogramVec

	weiToETH = big.NewInt(1e18)
)

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
	if auctionBlockUsed != nil {
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
	auctionBlockUsed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "relay_auction_block",
		Name:      "used_total",
		Help:      "The auction block provider used by a relay.",
	}, []string{"provider", "category"})
	if err := prometheus.Register(auctionBlockUsed); err != nil {
		return errors.Wrap(err, "failed to register vouch_relay_auction_block_used_total")
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
		return errors.Wrap(err, "failed to register vouch_relay_auction_block_duration_seconds")
	}

	bidDelta = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "builderbid_strategy",
		Name:      "bid_delta",
		Help:      "The absolute bid delta obtained by deadline strategy (ETH).",
		Buckets: []float64{
			0.0, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09,
			0.10, 0.11, 0.12, 0.13, 0.14, 0.15, 0.16, 0.17, 0.18, 0.19,
			0.20, 0.21, 0.22, 0.23, 0.24, 0.25, 0.26, 0.27, 0.28, 0.29,
			0.30, 0.31, 0.32, 0.33, 0.34, 0.35, 0.36, 0.37, 0.38, 0.39,
			0.40, 0.41, 0.42, 0.43, 0.44, 0.45, 0.46, 0.47, 0.48, 0.49,
		},
	}, []string{"provider"})
	if err := prometheus.Register(bidDelta); err != nil {
		return errors.Wrap(err, "failed to register vouch_builderbid_strategy_bid_delta")
	}

	bidPctDelta = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "builderbid_strategy",
		Name:      "bid_pctdelta",
		Help:      "The percentage bid delta obtained by deadline strategy.",
		Buckets: []float64{
			0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100,
		},
	}, []string{"provider"})
	if err := prometheus.Register(bidPctDelta); err != nil {
		return errors.Wrap(err, "failed to register vouch_builderbid_strategy_bid_pctdelta")
	}

	return nil
}

// monitorAuctionBlock provides metrics for an auction block operation.
func monitorAuctionBlock(provider string, category string, succeeded bool, duration time.Duration) {
	if auctionBlockUsed == nil {
		// Not yet registered.
		return
	}

	auctionBlockTimer.Observe(duration.Seconds())
	if succeeded {
		auctionBlockUsed.WithLabelValues(provider, category).Add(1)
	}
}

// monitorBidDelta provides metrics for bid deltas.
func monitorBidDelta(provider string, delta *big.Int, pctDelta float64) {
	if bidDelta == nil {
		// Not yet registered.
		return
	}

	// Move delta from Wei to ETH for metric.
	ethDelta := new(big.Int).Div(delta, weiToETH)
	bidDelta.WithLabelValues(provider).Observe(float64(ethDelta.Uint64()))

	// move pct delta from percentage to decimal.
	bidPctDelta.WithLabelValues(provider).Observe(pctDelta)
}
