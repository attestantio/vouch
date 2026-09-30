// Copyright © 2026 Attestant Limited.
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

	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/util"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	proposerPreferencesProcessEvents  *prometheus.CounterVec
	proposerPreferencesProviderEvents *prometheus.CounterVec
)

func registerMetrics(_ context.Context, monitor metrics.Service) error {
	if monitor == nil || monitor.Presenter() != "prometheus" {
		return nil
	}

	proposerPreferencesProcessEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "proposerpreferences_process",
		Name:      "events_total",
		Help:      "The number of proposer preferences process events.",
	}, []string{"outcome"})
	if err := prometheus.Register(proposerPreferencesProcessEvents); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			proposerPreferencesProcessEvents = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	proposerPreferencesProviderEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "proposerpreferences",
		Name:      "provider_events_total",
		Help:      "The number of proposer preferences events per proposal provider.",
	}, []string{"provider", "outcome"})
	if err := prometheus.Register(proposerPreferencesProviderEvents); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			proposerPreferencesProviderEvents = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	return nil
}

// monitorProposerPreferencesProvider records an outcome for a provider under its configured name,
// so endpoints never reach telemetry.
func monitorProposerPreferencesProvider(provider string, outcome string) {
	if proposerPreferencesProviderEvents == nil {
		return
	}
	proposerPreferencesProviderEvents.WithLabelValues(util.BeaconNodeName(provider), outcome).Inc()
}

func monitorProposerPreferencesProcess(outcome string) {
	if proposerPreferencesProcessEvents == nil {
		return
	}
	proposerPreferencesProcessEvents.WithLabelValues(outcome).Inc()
}
