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
	"fmt"
	"time"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	epochsProcessed                           prometheus.Counter
	blockReceiptDelay                         *prometheus.HistogramVec
	syncCommitteeVerificationHeadMismatches   *prometheus.CounterVec
	syncCommitteeVerificationAggregateFound   *prometheus.CounterVec
	syncCommitteeVerificationAggregateMissing *prometheus.CounterVec
	syncCommitteeVerificationGetHeadFailures  *prometheus.CounterVec
	syncCommitteeVerificationCurrentCount     prometheus.Gauge
)

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
	if monitor == nil {
		// No monitor.
		return nil
	}
	if monitor.Presenter() == "prometheus" {
		err := setupSyncCommitteeVerificationMetrics(ctx)
		if err != nil {
			return err
		}
		return registerPrometheusMetrics(ctx)
	}
	return nil
}

func registerPrometheusMetrics(_ context.Context) error {
	epochsProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "vouch",
		Name:      "epochs_processed_total",
		Help:      "The number of epochs vouch has processed.",
	})
	if err := prometheus.Register(epochsProcessed); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			epochsProcessed = alreadyRegisteredError.ExistingCollector.(prometheus.Counter)
		} else {
			return err
		}
	}

	blockReceiptDelay = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "vouch",
		Name:      "block_receipt_delay_seconds",
		Help:      "The delay between the start of a slot and the time vouch receives it.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.0,
			3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0,
			4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 5.0,
			5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 6.0,
			6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9, 7.0,
			7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9, 8.0,
			8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 9.0,
			9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9, 10.0,
			10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9, 11.0,
			11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8, 11.9, 12.0,
		},
	}, []string{"epoch_slot"})
	if err := prometheus.Register(blockReceiptDelay); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			blockReceiptDelay = alreadyRegisteredError.ExistingCollector.(*prometheus.HistogramVec)
		} else {
			return err
		}
	}

	return nil
}

func setupSyncCommitteeVerificationMetrics(_ context.Context) error {
	syncCommitteeVerificationHeadMismatches = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteeverification",
		Name:      "mismatches_total",
		Help:      "The number of sync committee messages we broadcast that did not match the next head root.",
	}, []string{})
	if err := prometheus.Register(syncCommitteeVerificationHeadMismatches); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			syncCommitteeVerificationHeadMismatches = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	syncCommitteeVerificationGetHeadFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteeverification",
		Name:      "get_head_failures_total",
		Help:      "The number of times sync committee verification failed due to being unable to retrieve the head block.",
	}, []string{})
	if err := prometheus.Register(syncCommitteeVerificationGetHeadFailures); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			syncCommitteeVerificationGetHeadFailures = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	syncCommitteeVerificationAggregateFound = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteeverification",
		Name:      "found_total",
		Help:      "The number of sync committee messages that were included in the sync aggregate.",
	}, []string{})
	if err := prometheus.Register(syncCommitteeVerificationAggregateFound); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			syncCommitteeVerificationAggregateFound = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	syncCommitteeVerificationAggregateMissing = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteeverification",
		Name:      "missing_total",
		Help:      "The number of sync committee messages that were not included in the sync aggregate.",
	}, []string{})
	if err := prometheus.Register(syncCommitteeVerificationAggregateMissing); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			syncCommitteeVerificationAggregateMissing = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	syncCommitteeVerificationCurrentCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "synccommitteeverification",
		Name:      "current_assigned",
		Help:      "The current number of sync committee assigned validators.",
	})
	if err := prometheus.Register(syncCommitteeVerificationCurrentCount); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			syncCommitteeVerificationCurrentCount = alreadyRegisteredError.ExistingCollector.(prometheus.Gauge)
		} else {
			return err
		}
	}

	return nil
}

func monitorNewEpoch() {
	if epochsProcessed == nil {
		return
	}
	epochsProcessed.Inc()
}

func monitorBlockDelay(epochSlot uint, delay time.Duration) {
	if blockReceiptDelay == nil {
		return
	}
	blockReceiptDelay.WithLabelValues(fmt.Sprintf("%d", epochSlot)).Observe(delay.Seconds())
}

func monitorSyncCommitteeSyncAggregateFoundInc() {
	if syncCommitteeVerificationAggregateFound == nil {
		return
	}
	syncCommitteeVerificationAggregateFound.WithLabelValues().Add(1)
}

func monitorSyncCommitteeSyncAggregateMissingInc() {
	if syncCommitteeVerificationAggregateMissing == nil {
		return
	}
	syncCommitteeVerificationAggregateMissing.WithLabelValues().Add(1)
}

func monitorSyncCommitteeGetHeadBlockFailedInc() {
	if syncCommitteeVerificationGetHeadFailures == nil {
		return
	}
	syncCommitteeVerificationGetHeadFailures.WithLabelValues().Add(1)
}

func monitorSyncCommitteeMessagesHeadMismatchInc(count int) {
	if syncCommitteeVerificationHeadMismatches == nil {
		return
	}
	syncCommitteeVerificationHeadMismatches.WithLabelValues().Add(float64(count))
}

func monitorSyncCommitteeCurrentCountSet(count int) {
	if syncCommitteeVerificationCurrentCount == nil {
		return
	}
	syncCommitteeVerificationCurrentCount.Set(float64(count))
}
