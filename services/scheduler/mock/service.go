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
func (*service) ScheduleJob(_ context.Context, _ string, _ string, _ time.Time, _ scheduler.JobFunc) error {
	return nil
}

// SchedulePeriodicJob schedules a job to run in a loop.
func (*service) SchedulePeriodicJob(_ context.Context, _ string, _ string, _ scheduler.RuntimeFunc, _ scheduler.JobFunc) error {
	return nil
}

// RunJob runs a named job immediately.
func (*service) RunJob(_ context.Context, _ string) error {
	return nil
}

// JobExists returns true if a job exists.
func (*service) JobExists(_ context.Context, _ string) bool {
	return false
}

// ListJobs returns the names of all jobs.
func (*service) ListJobs(_ context.Context) []string {
	return []string{}
}

// RunJobIfExists runs a job if it exists.
func (*service) RunJobIfExists(_ context.Context, _ string) {}

// CancelJob removes a named job.
func (*service) CancelJob(_ context.Context, _ string) error {
	return nil
}

// CancelJobIfExists cancels a job that may or may not exist.
func (*service) CancelJobIfExists(_ context.Context, _ string) {}

// CancelJobs cancels all jobs with the given prefix.
func (*service) CancelJobs(_ context.Context, _ string) {}
