// Copyright © 2025 Attestant Limited.
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

package majority

import (
	"context"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

var resultCounter *prometheus.CounterVec

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
	if resultCounter != nil {
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
	resultCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "strategy_attestationdata_majority",
		Name:      "result_total",
		Help:      "The result of obtaining attestation data.",
	}, []string{"result"})
	if err := prometheus.Register(resultCounter); err != nil {
		return errors.Wrap(err, "failed to register vouch_strategy_attestationdata_majority_result_total")
	}

	return nil
}

// monitorAttestationData provides metrics for an attestation data operation.
func monitorAttestationData(result string) {
	if resultCounter == nil {
		// Not yet registered.
		return
	}

	resultCounter.WithLabelValues(result).Inc()
}
