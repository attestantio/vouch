// Copyright © 2024 - 2026 Attestant Limited.
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

package staticdelay

import (
	"context"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	activeCounter *prometheus.CounterVec
	activeState   *prometheus.GaugeVec
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
	// Export every series from the start, so an increase() alert sees the first count.
	for _, operation := range []string{"attester", "proposer"} {
		for _, result := range []string{"active", "inactive", "unknown"} {
			activeCounter.WithLabelValues(operation, result).Add(0)
		}
	}

	activeState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "multiinstance",
		Name:      "active",
		Help:      "1 if this instance's last decision was to carry out the duty, otherwise 0",
	}, []string{"operation"})
	if err := prometheus.Register(activeState); err != nil {
		return errors.Wrap(err, "failed to register vouch_multiinstance_active")
	}

	return nil
}

// monitorActive provides metrics for the instance activity status.
func monitorActive(operation string, active bool) {
	if active {
		monitorDecision(operation, "active")
	} else {
		monitorDecision(operation, "inactive")
	}
}

// monitorUnknown records a stand-down because the check could not establish whether another instance acted.
func monitorUnknown(operation string) {
	monitorDecision(operation, "unknown")
}

// monitorDecision counts the result and sets the gauge to 1 only when the instance acts.
func monitorDecision(operation string, result string) {
	if activeCounter == nil {
		return
	}

	activeCounter.WithLabelValues(operation, result).Inc()
	state := 0.0
	if result == "active" {
		state = 1
	}
	activeState.WithLabelValues(operation).Set(state)
}
