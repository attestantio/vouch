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

package always

import (
	"context"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	activeCounter *prometheus.CounterVec
	activeState   prometheus.Gauge
)

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
	if activeCounter != nil {
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
	activeCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "multiinstance",
		Name:      "checks_total",
		Help:      "The number of checks for the active state",
	}, []string{"operation", "result"})
	if err := prometheus.Register(activeCounter); err != nil {
		return errors.Wrap(err, "failed to register vouch_multiinstance_checks_total")
	}

	activeState = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "multiinstance",
		Name:      "active",
		Help:      "1 if this instance is active, otherwise 0",
	})
	if err := prometheus.Register(activeState); err != nil {
		return errors.Wrap(err, "failed to register vouch_multiinstance_active")
	}

	return nil
}

// monitorActive provides metrics for the instance activity status.
func monitorActive(operation string, active bool) {
	if activeCounter == nil {
		return
	}

	if active {
		activeCounter.WithLabelValues(operation, "active").Inc()
		activeState.Set(1)
	} else {
		activeCounter.WithLabelValues(operation, "inactive").Inc()
		activeState.Set(0)
	}
}
