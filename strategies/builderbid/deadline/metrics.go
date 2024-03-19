// Copyright © 2023 Attestant Limited.
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

	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	auctionBlockUsed *prometheus.CounterVec
	bidDelta         *prometheus.HistogramVec
	bidPctDelta      *prometheus.HistogramVec

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
	}, []string{"provider"})
	if err := prometheus.Register(auctionBlockUsed); err != nil {
		return errors.Wrap(err, "failed to register vouch_relay_auction_block_used_total")
	}

	bidDelta = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "builderbid_strategy",
		Name:      "bid_delta",
		Help:      "The absolute bid delta obtained by deadline strategy (ETH).",
		Buckets: []float64{
			0.25, 0.5, 0.75, 1.0,
			1.25, 1.5, 1.75, 2.0,
			2.25, 2.5, 2.75, 3.0,
			3.25, 3.5, 3.75, 4.0,
			4.25, 4.5, 4.75, 5.0,
		},
	}, []string{"provider"})
	if err := prometheus.Register(bidDelta); err != nil {
		return errors.Wrap(err, "failed to register vouch_builderbid_strategy_bid_delta")
	}

	bidPctDelta = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "builderbid_strategy",
		Name:      "bid_pctdelta",
		Help:      "The percentage bid delta obtained by deadline strategy (ETH).",
		Buckets: []float64{
			10, 20, 30, 40, 50, 60, 70, 80, 90, 100,
		},
	}, []string{"provider"})
	if err := prometheus.Register(bidPctDelta); err != nil {
		return errors.Wrap(err, "failed to register vouch_builderbid_strategy_bid_pctdelta")
	}

	return nil
}

// monitorAuctionBlock provides metrics for an auction block operation.
func monitorAuctionBlock(provider string, succeeded bool) {
	if auctionBlockUsed == nil {
		// Not yet registered.
		return
	}

	if succeeded {
		auctionBlockUsed.WithLabelValues(provider).Add(1)
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
