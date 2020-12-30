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

package mock

import (
	"context"
	"time"

	"github.com/attestantio/vouch/services/scheduler"
)

// Service is a mock scheduler service.
type service struct{}

// New creates a new mock scheduling service.
func New() scheduler.Service {
	return &service{}
}

// ScheduleJob schedules a one-off job for a given time.
func (s *service) ScheduleJob(ctx context.Context, name string, runtime time.Time, jobFunc scheduler.JobFunc, data interface{}) error {
	return nil
}

// SchedulePeriodicJob schedules a job to run in a loop.
func (s *service) SchedulePeriodicJob(ctx context.Context, name string, runtimeFunc scheduler.RuntimeFunc, runtimeData interface{}, jobFunc scheduler.JobFunc, jobData interface{}) error {
	return nil
}

// RunJob runs a named job immediately.
func (s *service) RunJob(ctx context.Context, name string) error {
	return nil
}

// JobExists returns true if a job exists.
func (s *service) JobExists(ctx context.Context, name string) bool {
	return false
}

// ListJobs returns the names of all jobs.
func (s *service) ListJobs(ctx context.Context) []string {
	return []string{}
}

// RunJobIfExists runs a job if it exists.
func (s *service) RunJobIfExists(ctx context.Context, name string) error {
	return nil
}

// CancelJob removes a named job.
func (s *service) CancelJob(ctx context.Context, name string) error {
	return nil
}

// CancelJobs cancels all jobs with the given prefix.
func (s *service) CancelJobs(ctx context.Context, prefix string) error {
	return nil
}
