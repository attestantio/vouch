// Copyright © 2020 - 2023 Attestant Limited.
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

package prometheus

import (
	"context"
	"net/http"
	"time"

	"github.com/attestantio/vouch/services/chaintime"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is a metrics service exposing metrics via prometheus.
type Service struct {
	chainTime chaintime.Service

	schedulerJobsScheduled *prometheus.CounterVec
	schedulerJobsCancelled *prometheus.CounterVec
	schedulerJobsStarted   *prometheus.CounterVec

	epochsProcessed   prometheus.Counter
	blockReceiptDelay *prometheus.HistogramVec

	attestationProcessTimer      prometheus.Histogram
	attestationProcessRequests   *prometheus.CounterVec
	attestationMarkTimer         prometheus.Histogram
	attestationProcessLatestSlot prometheus.Gauge

	attestationAggregationProcessTimer      prometheus.Histogram
	attestationAggregationProcessRequests   *prometheus.CounterVec
	attestationAggregationCoverageRatio     prometheus.Histogram
	attestationAggregationMarkTimer         prometheus.Histogram
	attestationAggregationProcessLatestSlot prometheus.Gauge

	syncCommitteeMessageProcessTimer      prometheus.Histogram
	syncCommitteeMessageProcessRequests   *prometheus.CounterVec
	syncCommitteeMessageMarkTimer         prometheus.Histogram
	syncCommitteeMessageProcessLatestSlot prometheus.Gauge

	syncCommitteeVerificationHeadMismatches   *prometheus.CounterVec
	syncCommitteeVerificationAggregateFound   *prometheus.CounterVec
	syncCommitteeVerificationAggregateMissing *prometheus.CounterVec
	syncCommitteeVerificationGetHeadFailures  *prometheus.CounterVec
	syncCommitteeVerificationCurrentCount     prometheus.Gauge

	syncCommitteeAggregationProcessTimer      prometheus.Histogram
	syncCommitteeAggregationProcessRequests   *prometheus.CounterVec
	syncCommitteeAggregationCoverageRatio     prometheus.Histogram
	syncCommitteeAggregationMarkTimer         prometheus.Histogram
	syncCommitteeAggregationProcessLatestSlot prometheus.Gauge

	beaconCommitteeSubscriptionProcessTimer    prometheus.Histogram
	beaconCommitteeSubscriptionProcessRequests *prometheus.CounterVec
	beaconCommitteeSubscribers                 prometheus.Gauge
	beaconCommitteeAggregators                 prometheus.Gauge

	syncCommitteeSubscriptionProcessTimer    prometheus.Histogram
	syncCommitteeSubscriptionProcessRequests *prometheus.CounterVec
	syncCommitteeSubscribers                 prometheus.Gauge

	accountManagerAccounts *prometheus.GaugeVec

	clientOperationCounter   *prometheus.CounterVec
	clientOperationTimer     *prometheus.HistogramVec
	strategyOperationCounter *prometheus.CounterVec
	strategyOperationTimer   *prometheus.HistogramVec
}

// module-wide log.
var log zerolog.Logger

// New creates a new prometheus metrics service.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "metrics").Str("impl", "prometheus").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		chainTime: parameters.chainTime,
	}

	if err := s.setupSchedulerMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up scheduler metrics")
	}
	if err := s.setupControllerMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up controller metrics")
	}
	if err := s.setupAttestationMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up attestation metrics")
	}
	if err := s.setupAttestationAggregationMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up attestation aggregation metrics")
	}
	if err := s.setupAllSyncCommitteeMetrics(); err != nil {
		return nil, err
	}
	if err := s.setupBeaconCommitteeSubscriptionMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up beacon committee subscription metrics")
	}
	if err := s.setupSyncCommitteeSubscriptionMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up sync committee subscription metrics")
	}
	if err := s.setupAccountManagerMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up account manager metrics")
	}
	if err := s.setupClientMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up client metrics")
	}

	if parameters.createServer {
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			server := &http.Server{
				Addr:              parameters.address,
				ReadHeaderTimeout: 5 * time.Second,
			}
			if err := server.ListenAndServe(); err != nil {
				log.Warn().Str("metrics_address", parameters.address).Err(err).Msg("Failed to run metrics server")
			}
		}()
	}

	return s, nil
}

func (s *Service) setupAllSyncCommitteeMetrics() error {
	if err := s.setupSyncCommitteeMessageMetrics(); err != nil {
		return errors.Wrap(err, "failed to set up sync committee message metrics")
	}
	if err := s.setupSyncCommitteeVerificationMetrics(); err != nil {
		return errors.Wrap(err, "failed to set up sync committee validation metrics")
	}
	if err := s.setupSyncCommitteeAggregationMetrics(); err != nil {
		return errors.Wrap(err, "failed to set up sync committee aggregation metrics")
	}
	return nil
}

// Presenter returns the presenter for the events.
func (*Service) Presenter() string {
	return "prometheus"
}
