// Copyright © 2021 Attestant Limited.
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
	"strings"
	"time"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/sasha-s/go-deadlock"
	"go.uber.org/atomic"
)

// module-wide log.
var log zerolog.Logger

// job contains control points for a job.
type job struct {
	// stateLock is required for active or finalised.
	stateLock deadlock.Mutex
	active    atomic.Bool
	finalised atomic.Bool
	cancelCh  chan struct{}
	runCh     chan struct{}
}

// Service is a scheduler service.  It uses additional per-job information to manage
// the state of each job, in an attempt to ensure additional robustness in the face
// of high concurrent load.
type Service struct {
	monitor   metrics.SchedulerMonitor
	jobs      map[string]*job
	jobsMutex deadlock.RWMutex
}

// New creates a new scheduling service.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "scheduler").Str("impl", "advanced").Logger()
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

	s.jobsMutex.Lock()
	_, exists := s.jobs[name]
	if exists {
		s.jobsMutex.Unlock()
		return scheduler.ErrJobAlreadyExists
	}

	job := &job{
		cancelCh: make(chan struct{}),
		runCh:    make(chan struct{}),
	}
	s.jobs[name] = job
	s.jobsMutex.Unlock()
	s.monitor.JobScheduled()

	log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Scheduled job")
	go func() {
		select {
		case <-ctx.Done():
			log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Parent context done; job not running")
			s.jobsMutex.Lock()
			delete(s.jobs, name)
			s.jobsMutex.Unlock()
			finaliseJob(job)
			s.monitor.JobCancelled()
		case <-job.cancelCh:
			log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Cancel triggered; job not running")
			finaliseJob(job)
			s.monitor.JobCancelled()
		case <-job.runCh:
			log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Run triggered; job running")
			s.monitor.JobStartedOnSignal()
			jobFunc(ctx, data)
			log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Job complete")
			finaliseJob(job)
			job.active.Store(false)
		case <-time.After(time.Until(runtime)):
			log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Timer triggered; job running")
			job.stateLock.Lock()
			job.active.Store(true)
			job.stateLock.Unlock()
			s.monitor.JobStartedOnTimer()
			jobFunc(ctx, data)
			log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Job complete")
			job.active.Store(false)
			finaliseJob(job)
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

	s.jobsMutex.Lock()
	_, exists := s.jobs[name]
	if exists {
		s.jobsMutex.Unlock()
		return scheduler.ErrJobAlreadyExists
	}

	job := &job{
		cancelCh: make(chan struct{}),
		runCh:    make(chan struct{}),
	}
	s.jobs[name] = job
	s.jobsMutex.Unlock()
	s.monitor.JobScheduled()

	go func() {
		for {
			runtime, err := runtimeFunc(ctx, runtimeData)
			if err == scheduler.ErrNoMoreInstances {
				log.Trace().Str("job", name).Msg("No more instances; period job stopping")
				s.jobsMutex.Lock()
				delete(s.jobs, name)
				s.jobsMutex.Unlock()
				finaliseJob(job)
				s.monitor.JobCancelled()
				return
			}
			if err != nil {
				log.Error().Str("job", name).Err(err).Msg("Failed to obtain runtime; periodic job stopping")
				s.jobsMutex.Lock()
				delete(s.jobs, name)
				s.jobsMutex.Unlock()
				finaliseJob(job)
				s.monitor.JobCancelled()
				return
			}
			log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Scheduled job")
			select {
			case <-ctx.Done():
				log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Parent context done; job not running")
				s.jobsMutex.Lock()
				delete(s.jobs, name)
				s.jobsMutex.Unlock()
				finaliseJob(job)
				s.monitor.JobCancelled()
				return
			case <-job.cancelCh:
				log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Cancel triggered; job not running")
				finaliseJob(job)
				s.monitor.JobCancelled()
				return
			case <-job.runCh:
				log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Run triggered; job running")
				s.monitor.JobStartedOnSignal()
				jobFunc(ctx, jobData)
				log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Job complete")
				job.active.Store(false)
			case <-time.After(time.Until(runtime)):
				job.active.Store(true)
				log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Timer triggered; job running")
				s.monitor.JobStartedOnTimer()
				jobFunc(ctx, jobData)
				log.Trace().Str("job", name).Time("scheduled", runtime).Msg("Job complete")
				job.active.Store(false)
			}
		}
	}()

	return nil
}

// RunJob runs a named job immediately.
// If the job does not exist it will return an appropriate error.
func (s *Service) RunJob(ctx context.Context, name string) error {
	s.jobsMutex.Lock()
	job, exists := s.jobs[name]
	s.jobsMutex.Unlock()

	if !exists {
		return scheduler.ErrNoSuchJob
	}

	return s.runJob(ctx, job)
}

// RunJobIfExists runs a job if it exists.
// This does not return an error if the job does not exist or is otherwise unable to run.
func (s *Service) RunJobIfExists(ctx context.Context, name string) {
	s.jobsMutex.Lock()
	job, exists := s.jobs[name]
	s.jobsMutex.Unlock()

	if !exists {
		return
	}
	//nolint
	s.runJob(ctx, job)

}

// JobExists returns true if a job exists.
func (s *Service) JobExists(ctx context.Context, name string) bool {
	s.jobsMutex.RLock()
	_, exists := s.jobs[name]
	s.jobsMutex.RUnlock()
	return exists
}

// ListJobs returns the names of all jobs.
func (s *Service) ListJobs(ctx context.Context) []string {
	s.jobsMutex.RLock()
	names := make([]string, 0, len(s.jobs))
	for name := range s.jobs {
		names = append(names, name)
	}
	s.jobsMutex.RUnlock()

	return names
}

// CancelJob removes a named job.
// If the job does not exist it will return an appropriate error.
func (s *Service) CancelJob(ctx context.Context, name string) error {
	s.jobsMutex.Lock()
	job, exists := s.jobs[name]
	if !exists {
		s.jobsMutex.Unlock()
		return scheduler.ErrNoSuchJob
	}
	delete(s.jobs, name)
	s.jobsMutex.Unlock()

	job.stateLock.Lock()
	if job.finalised.Load() {
		// Already marked to be cancelled.
		job.stateLock.Unlock()
		return nil
	}
	job.finalised.Store(true)
	job.cancelCh <- struct{}{}
	job.stateLock.Unlock()

	return nil
}

// CancelJobIfExists cancels a job that may or may not exist.
// If this is a period job then all future instances are cancelled.
func (s *Service) CancelJobIfExists(ctx context.Context, name string) {
	//nolint
	s.CancelJob(ctx, name)
}

// CancelJobs cancels all jobs with the given prefix.
// If the prefix matches a period job then all future instances are cancelled.
func (s *Service) CancelJobs(ctx context.Context, prefix string) {
	names := make([]string, 0)
	s.jobsMutex.Lock()
	for name := range s.jobs {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	s.jobsMutex.Unlock()

	for _, name := range names {
		// It is possible that the job has been removed whist we were iterating, so use the non-erroring version of cancel.
		s.CancelJobIfExists(ctx, name)
	}
}

// finaliseJob tidies up a job that is no longer in use.
func finaliseJob(job *job) {
	job.stateLock.Lock()
	job.finalised.Store(true)

	// Close the channels for the job to ensure that nothing is hanging on sending a message.
	close(job.cancelCh)
	close(job.runCh)

	job.stateLock.Unlock()
}

// runJob runs the given job.
func (s *Service) runJob(ctx context.Context, job *job) error {
	job.stateLock.Lock()
	if job.active.Load() {
		job.stateLock.Unlock()
		return scheduler.ErrJobRunning
	}
	if job.finalised.Load() {
		job.stateLock.Unlock()
		return scheduler.ErrJobFinalised
	}
	job.active.Store(true)
	job.runCh <- struct{}{}
	job.stateLock.Unlock()

	return nil
}
