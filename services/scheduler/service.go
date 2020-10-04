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

package scheduler

import (
	"context"
	"errors"
	"time"
)

// JobFunc is the type for jobs.
type JobFunc func(context.Context, interface{})

// RuntimeFunc is the type of a function that generates the next runtime.
type RuntimeFunc func(context.Context, interface{}) (time.Time, error)

// ErrNoMoreInstances is returned by the runtime generator when it has no more instances.
var ErrNoMoreInstances = errors.New("no more instances")

// ErrNoSuchJob is returned when the scheduler is asked to act upon a job about which it has no information.
var ErrNoSuchJob = errors.New("no such job")

// ErrJobAlreadyExists is returned when the scheduler is asked to create a job that already exists.
var ErrJobAlreadyExists = errors.New("job already exists")

// ErrNoJobName is returned when an attempt is made to to control a job without a name.
var ErrNoJobName = errors.New("no job name")

// ErrNoJobFunc is returned when an attempt is made to to run a nil job.
var ErrNoJobFunc = errors.New("no job function")

// ErrNoRuntimeFunc is returned when an attempt is made to to run a periodic job without a runtime function.
var ErrNoRuntimeFunc = errors.New("no runtime function")

// Service is the interface for schedulers.
type Service interface {
	// ScheduleJob schedules a one-off job for a given time.
	// This function returns two cancel funcs.  If the first is triggered the job will not run.  If the second is triggered the job
	// runs immediately.
	// Note that if the parent context is cancelled the job wil not run.
	ScheduleJob(ctx context.Context, name string, runtime time.Time, job JobFunc, data interface{}) error

	// SchedulePeriodicJob schedules a job to run in a loop.
	SchedulePeriodicJob(ctx context.Context, name string, runtime RuntimeFunc, runtineData interface{}, job JobFunc, jobData interface{}) error

	// CancelJob cancels a known job.
	// If this is a period job then all future instances are cancelled.
	CancelJob(ctx context.Context, name string) error

	// CancelJobs cancels all jobs with the given prefix.
	// If the prefix matches a period job then all future instances are cancelled.
	CancelJobs(ctx context.Context, prefix string) error

	// RunJob runs a known job.
	// If this is a period job then the next instance will be scheduled.
	RunJob(ctx context.Context, name string) error

	// JobExists returns true if a job exists.
	JobExists(ctx context.Context, name string) bool

	// RunJobIfExists runs a job if it exists.
	// This does not return an error if the job does not exist.
	// If this is a period job then the next instance will be scheduled.
	RunJobIfExists(ctx context.Context, name string) error

	// ListJobs returns the names of all jobs.
	ListJobs(ctx context.Context) []string
}
