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

package basic

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/sasha-s/go-deadlock"
)

// module-wide log.
var log zerolog.Logger

// job contains control points for a job.
type job struct {
	cancelCh chan struct{}
	runCh    chan struct{}
	mutex    deadlock.Mutex
}

// Service is a controller service.
type Service struct {
	monitor metrics.SchedulerMonitor
	jobs    map[string]*job
	mutex   deadlock.RWMutex
}

// New creates a new scheduling service.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "scheduler").Str("impl", "basic").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	return &Service{
		jobs:    make(map[string]*job),
		monitor: parameters.monitor,
	}, nil
}

// ScheduleJob schedules a one-off job for a given time.
// Note that if the parent context is cancelled the job wil not run.
func (s *Service) ScheduleJob(ctx context.Context, name string, runtime time.Time, jobFunc scheduler.JobFunc, data interface{}) error {
	if name == "" {
		return scheduler.ErrNoJobName
	}
	if jobFunc == nil {
		return scheduler.ErrNoJobFunc
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.jobs[name]; exists {
		return scheduler.ErrJobAlreadyExists
	}

	cancelCh := make(chan struct{})
	runCh := make(chan struct{})
	s.jobs[name] = &job{
		cancelCh: cancelCh,
		runCh:    runCh,
	}
	s.monitor.JobScheduled()

	log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Scheduled job")
	go func() {
		select {
		case <-ctx.Done():
			log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Parent context done; job not running")
			s.mutex.Lock()
			s.removeJob(ctx, name)
			s.mutex.Unlock()
			s.monitor.JobCancelled()
		case <-cancelCh:
			log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Cancel triggered; job not running")
			// The job will have been removed by the function that sent the cancel.
			s.monitor.JobCancelled()
		case <-runCh:
			s.mutex.Lock()
			if s.jobExists(ctx, name) {
				s.removeJob(ctx, name)
				s.mutex.Unlock()
				log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Run triggered; job running")
				s.monitor.JobStartedOnSignal()
				jobFunc(ctx, data)
				log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Job complete")
			} else {
				// Job has been taken by another thread; do nothing.
				s.mutex.Unlock()
			}
		case <-time.After(time.Until(runtime)):
			s.mutex.Lock()
			if s.jobExists(ctx, name) {
				s.removeJob(ctx, name)
				s.mutex.Unlock()
				log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Timer triggered; job running")
				s.monitor.JobStartedOnTimer()
				jobFunc(ctx, data)
				log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Job complete")
			} else {
				// Job has been taken by another thread; do nothing.
				s.mutex.Unlock()
			}
		}
	}()

	return nil
}

// SchedulePeriodicJob schedules a job to run in a loop.
// The loop starts by calling runtimeFunc, which sets the time for the first run.
// Once the time as specified by runtimeFunc is met, jobFunc is called.
// Once jobFunc returns, go back to the beginning of the loop.
func (s *Service) SchedulePeriodicJob(ctx context.Context, name string, runtimeFunc scheduler.RuntimeFunc, runtimeData interface{}, jobFunc scheduler.JobFunc, jobData interface{}) error {
	if name == "" {
		return scheduler.ErrNoJobName
	}
	if runtimeFunc == nil {
		return scheduler.ErrNoRuntimeFunc
	}
	if jobFunc == nil {
		return scheduler.ErrNoJobFunc
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.jobs[name]; exists {
		return scheduler.ErrJobAlreadyExists
	}

	cancelCh := make(chan struct{})
	runCh := make(chan struct{})
	s.jobs[name] = &job{
		cancelCh: cancelCh,
		runCh:    runCh,
	}
	s.monitor.JobScheduled()

	go func() {
		for {
			runtime, err := runtimeFunc(ctx, runtimeData)
			if err == scheduler.ErrNoMoreInstances {
				log.Trace().Str("job", name).Msg("No more instances; period job stopping")
				s.mutex.Lock()
				s.removeJob(ctx, name)
				s.mutex.Unlock()
				s.monitor.JobCancelled()
				return
			}
			if err != nil {
				log.Error().Str("job", name).Err(err).Msg("Failed to obtain runtime; periodic job stopping")
				s.mutex.Lock()
				s.removeJob(ctx, name)
				s.mutex.Unlock()
				s.monitor.JobCancelled()
				return
			}
			log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Scheduled job")
			select {
			case <-ctx.Done():
				log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Parent context done; job not running")
				s.mutex.Lock()
				s.removeJob(ctx, name)
				s.mutex.Unlock()
				s.monitor.JobCancelled()
				return
			case <-cancelCh:
				log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Cancel triggered; job not running")
				// The job will have been removed by the function that sent the cancel.
				s.monitor.JobCancelled()
				return
			case <-runCh:
				s.mutex.Lock()
				s.lockJob(ctx, name)
				s.mutex.Unlock()
				log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Run triggered; job running")
				s.monitor.JobStartedOnSignal()
				jobFunc(ctx, jobData)
				log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Job complete")
				s.unlockJob(ctx, name)
			case <-time.After(time.Until(runtime)):
				s.mutex.Lock()
				s.lockJob(ctx, name)
				s.mutex.Unlock()
				log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Timer triggered; job running")
				s.monitor.JobStartedOnTimer()
				jobFunc(ctx, jobData)
				log.Trace().Str("job", name).Str("scheduled", fmt.Sprintf("%v", runtime)).Msg("Job complete")
				s.unlockJob(ctx, name)
			}
		}
	}()

	return nil
}

// RunJob runs a named job immediately.
// If the job does not exist it will return an appropriate error.
func (s *Service) RunJob(ctx context.Context, name string) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	job, exists := s.jobs[name]
	if !exists {
		return scheduler.ErrNoSuchJob
	}

	job.runCh <- struct{}{}
	return nil
}

// JobExists returns true if a job exists.
func (s *Service) JobExists(ctx context.Context, name string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	_, exists := s.jobs[name]
	return exists
}

// ListJobs returns the names of all jobs.
func (s *Service) ListJobs(ctx context.Context) []string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	names := make([]string, 0, len(s.jobs))
	for name := range s.jobs {
		names = append(names, name)
	}

	return names
}

// RunJobIfExists runs a job if it exists.
// This does not return an error if the job does not exist.
func (s *Service) RunJobIfExists(ctx context.Context, name string) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if job, exists := s.jobs[name]; exists {
		job.runCh <- struct{}{}
	}
	return nil
}

// CancelJob removes a named job.
// If the job does not exist it will return an appropriate error.
func (s *Service) CancelJob(ctx context.Context, name string) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	job, exists := s.jobs[name]
	if !exists {
		return scheduler.ErrNoSuchJob
	}

	job.cancelCh <- struct{}{}
	s.removeJob(ctx, name)

	return nil
}

// CancelJobs cancels all jobs with the given prefix.
// If the prefix matches a period job then all future instances are cancelled.
func (s *Service) CancelJobs(ctx context.Context, prefix string) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	for name, job := range s.jobs {
		if strings.HasPrefix(name, prefix) {
			job.cancelCh <- struct{}{}
			s.removeJob(ctx, name)
		}
	}

	return nil
}

// jobExists returns true if the job exists in the job list.
// This assumes that the service mutex is held.
func (s *Service) jobExists(ctx context.Context, name string) bool {
	_, exists := s.jobs[name]
	return exists
}

// removeJob is an internal function to remove a named job.  It will fail silently if the job does not exist.
// This assumes that the service mutex is held.
func (s *Service) removeJob(ctx context.Context, name string) {
	delete(s.jobs, name)
}

// lockJob locks a specific job.
// This assumes that the service mutex is held.
func (s *Service) lockJob(ctx context.Context, name string) {
	job, exists := s.jobs[name]
	if !exists {
		return
	}
	job.mutex.Lock()
}

// unlockJob unlocks a specific job.
// This should be called without the service mutex held, to avoid lock<>lock<>unlock situations.
func (s *Service) unlockJob(ctx context.Context, name string) {
	job, exists := s.jobs[name]
	if !exists {
		return
	}
	job.mutex.Unlock()
}
