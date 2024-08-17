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

package advanced

import (
	"context"
	"errors"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	schedulerJobsScheduled *prometheus.CounterVec
	schedulerJobsCancelled *prometheus.CounterVec
	schedulerJobsStarted   *prometheus.CounterVec
)

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
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
	schedulerJobsScheduled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "scheduler",
		Name:      "jobs_scheduled_total",
		Help:      "The number of jobs scheduled.",
	}, []string{"class"})
	if err := prometheus.Register(schedulerJobsScheduled); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			schedulerJobsScheduled = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	schedulerJobsCancelled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "scheduler",
		Name:      "jobs_cancelled_total",
		Help:      "The number of scheduled jobs cancelled.",
	}, []string{"class"})
	if err := prometheus.Register(schedulerJobsCancelled); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			schedulerJobsCancelled = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	schedulerJobsStarted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "scheduler",
		Name:      "jobs_started_total",
		Help:      "The number of scheduled jobs started.",
	}, []string{"class", "trigger"})
	if err := prometheus.Register(schedulerJobsStarted); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			schedulerJobsStarted = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	return nil
}

func monitorJobScheduled(class string) {
	if schedulerJobsScheduled == nil {
		return
	}
	schedulerJobsScheduled.WithLabelValues(class).Inc()
}

func monitorJobCancelled(class string) {
	if schedulerJobsCancelled == nil {
		return
	}
	schedulerJobsCancelled.WithLabelValues(class).Inc()
}

func monitorJobStartedOnTimer(class string) {
	if schedulerJobsStarted == nil {
		return
	}
	schedulerJobsStarted.WithLabelValues(class, "timer").Inc()
}

func monitorJobStartedOnSignal(class string) {
	if schedulerJobsStarted == nil {
		return
	}
	schedulerJobsStarted.WithLabelValues(class, "signal").Inc()
}
