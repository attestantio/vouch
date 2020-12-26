// Copyright © 2020 Attestant Limited.
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

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is a metrics service exposing metrics via prometheus.
type Service struct {
	schedulerJobsScheduled prometheus.Counter
	schedulerJobsCancelled prometheus.Counter
	schedulerJobsStarted   *prometheus.CounterVec

	epochsProcessed   prometheus.Counter
	blockReceiptDelay *prometheus.HistogramVec

	beaconBlockProposalProcessTimer    prometheus.Histogram
	beaconBlockProposalProcessRequests *prometheus.CounterVec

	attestationProcessTimer    prometheus.Histogram
	attestationProcessRequests *prometheus.CounterVec

	attestationAggregationProcessTimer    prometheus.Histogram
	attestationAggregationProcessRequests *prometheus.CounterVec
	attestationAggregationCoverageRatio   prometheus.Histogram

	beaconCommitteeSubscriptionProcessTimer    prometheus.Histogram
	beaconCommitteeSubscriptionProcessRequests *prometheus.CounterVec
	beaconCommitteeSubscribers                 prometheus.Gauge
	beaconCommitteeAggregators                 prometheus.Gauge

	accountManagerAccounts *prometheus.GaugeVec

	clientOperationCounter *prometheus.CounterVec
	clientOperationTimer   *prometheus.HistogramVec
}

// module-wide log.
var log zerolog.Logger

// New creates a new prometheus metrics service.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "metrics").Str("impl", "prometheus").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{}

	if err := s.setupSchedulerMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up scheduler metrics")
	}
	if err := s.setupControllerMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up controller metrics")
	}
	if err := s.setupBeaconBlockProposalMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up beacon block proposal metrics")
	}
	if err := s.setupAttestationMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up attestation metrics")
	}
	if err := s.setupAttestationAggregationMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up attestation aggregation metrics")
	}
	if err := s.setupBeaconCommitteeSubscriptionMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up beacon committee subscription metrics")
	}
	if err := s.setupAccountManagerMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up account manager metrics")
	}
	if err := s.setupClientMetrics(); err != nil {
		return nil, errors.Wrap(err, "failed to set up client metrics")
	}

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(parameters.address, nil); err != nil {
			log.Warn().Str("metrics_address", parameters.address).Err(err).Msg("Failed to run metrics server")
		}
	}()

	return s, nil
}
