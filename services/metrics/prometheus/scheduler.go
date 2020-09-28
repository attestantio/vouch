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
	"github.com/prometheus/client_golang/prometheus"
)

func (s *Service) setupSchedulerMetrics() error {
	s.schedulerJobsScheduled = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "scheduler",
		Name:      "jobs_scheduled_total",
		Help:      "The total number of jobs scheduled.",
	})
	if err := prometheus.Register(s.schedulerJobsScheduled); err != nil {
		return err
	}

	s.schedulerJobsCancelled = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "scheduler",
		Name:      "jobs_cancelled_total",
		Help:      "The total number of scheduled jobs cancelled.",
	})
	if err := prometheus.Register(s.schedulerJobsCancelled); err != nil {
		return err
	}

	s.schedulerJobsStarted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "scheduler",
		Name:      "jobs_started_total",
		Help:      "The total number of scheduled jobs started.",
	}, []string{"trigger"})
	if err := prometheus.Register(s.schedulerJobsStarted); err != nil {
		return err
	}

	return nil
}

// JobScheduled is called when a job is scheduled.
func (s *Service) JobScheduled() {
	s.schedulerJobsScheduled.Inc()
}

// JobCancelled is called when a scheduled job is cancelled.
func (s *Service) JobCancelled() {
	s.schedulerJobsCancelled.Inc()
}

// JobStartedOnTimer is called when a scheduled job is started due to meeting its time.
func (s *Service) JobStartedOnTimer() {
	s.schedulerJobsStarted.WithLabelValues("timer").Inc()
}

// JobStartedOnSignal is called when a scheduled job is started due to being manually signalled.
func (s *Service) JobStartedOnSignal() {
	s.schedulerJobsStarted.WithLabelValues("signal").Inc()
}
