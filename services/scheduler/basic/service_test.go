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

package basic_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/attestantio/vouch/services/scheduler/basic"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		options []basic.Parameter
		err     string
	}{
		{
			name: "Good",
		},
		{
			name: "GoodLogLevel",
			options: []basic.Parameter{
				basic.WithLogLevel(zerolog.Disabled),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := basic.New(ctx, test.options...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, s)
			}
		})
	}
}

func TestJob(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(100*time.Millisecond), runFunc, nil))
	require.Equal(t, 0, run)
	time.Sleep(time.Duration(110) * time.Millisecond)
	assert.Equal(t, 1, run)
}

func TestJobExists(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(10*time.Second), runFunc, nil))

	require.True(t, s.JobExists(ctx, "Test job"))
	require.False(t, s.JobExists(ctx, "Unknown job"))

	require.NoError(t, s.CancelJob(ctx, "Test job"))
}

func TestCancelJob(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(100*time.Millisecond), runFunc, nil))
	require.Equal(t, 0, run)
	require.NoError(t, s.CancelJob(ctx, "Test job"))
	time.Sleep(time.Duration(110) * time.Millisecond)
	assert.Equal(t, 0, run)
}

func TestCancelUnknownJob(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	assert.EqualError(t, s.CancelJob(ctx, "Unknown job"), scheduler.ErrNoSuchJob.Error())
}

func TestCancelJobs(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job 1", time.Now().Add(100*time.Millisecond), runFunc, nil))
	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job 2", time.Now().Add(100*time.Millisecond), runFunc, nil))
	require.NoError(t, s.ScheduleJob(ctx, "Test", "No cancel job", time.Now().Add(100*time.Millisecond), runFunc, nil))
	require.Equal(t, 0, run)
	s.CancelJobs(ctx, "Test job")
	time.Sleep(time.Duration(110) * time.Millisecond)
	assert.Equal(t, 1, run)
}

func TestCancelParentContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(100*time.Millisecond), runFunc, nil))
	require.Equal(t, 0, run)
	cancel()
	time.Sleep(time.Duration(110) * time.Millisecond)
	assert.Equal(t, 0, run)
}

func TestRunJob(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(time.Second), runFunc, nil))
	require.Equal(t, 0, run)
	require.NoError(t, s.RunJob(ctx, "Test job"))
	time.Sleep(time.Duration(100) * time.Millisecond)
	assert.Equal(t, 1, run)
}

func TestRunJobIfExists(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(time.Second), runFunc, nil))
	require.Equal(t, 0, run)
	s.RunJobIfExists(ctx, "Unknown job")
	require.Equal(t, 0, run)
	s.RunJobIfExists(ctx, "Test job")
	time.Sleep(time.Duration(100) * time.Millisecond)
	assert.Equal(t, 1, run)
}

func TestRunUnknownJob(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	assert.EqualError(t, s.RunJob(ctx, "Unknown job"), scheduler.ErrNoSuchJob.Error())
}

func TestPeriodicJob(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	runtimeFunc := func(ctx context.Context, data interface{}) (time.Time, error) {
		return time.Now().Add(100 * time.Millisecond), nil
	}

	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test periodic job", runtimeFunc, nil, runFunc, nil))
	require.Equal(t, 0, run)
	time.Sleep(time.Duration(110) * time.Millisecond)
	assert.Equal(t, 1, run)
	time.Sleep(time.Duration(110) * time.Millisecond)
	assert.Equal(t, 2, run)
	require.NoError(t, s.RunJob(ctx, "Test periodic job"))
	time.Sleep(time.Duration(10) * time.Millisecond)
	assert.Equal(t, 3, run)
}

func TestCancelPeriodicJob(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	runtimeFunc := func(ctx context.Context, data interface{}) (time.Time, error) {
		return time.Now().Add(100 * time.Millisecond), nil
	}

	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test periodic job", runtimeFunc, nil, runFunc, nil))
	require.Equal(t, 0, run)
	require.NoError(t, s.CancelJob(ctx, "Test periodic job"))
	time.Sleep(time.Duration(110) * time.Millisecond)
	assert.Equal(t, 0, run)
}

func TestCancelPeriodicParentContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	runtimeFunc := func(ctx context.Context, data interface{}) (time.Time, error) {
		return time.Now().Add(100 * time.Millisecond), nil
	}

	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test job", runtimeFunc, nil, runFunc, nil))
	require.Equal(t, 0, run)
	cancel()
	time.Sleep(time.Duration(110) * time.Millisecond)
	assert.Equal(t, 0, run)
}

func TestLimitedPeriodicJob(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	runtimeFunc := func(ctx context.Context, data interface{}) (time.Time, error) {
		if run == 3 {
			return time.Now(), scheduler.ErrNoMoreInstances
		}
		return time.Now().Add(10 * time.Millisecond), nil
	}

	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test job", runtimeFunc, nil, runFunc, nil))
	require.Equal(t, 0, run)
	time.Sleep(time.Duration(50) * time.Millisecond)
	assert.Equal(t, 3, run)
}

func TestBadPeriodicJob(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	runtimeFunc := func(ctx context.Context, data interface{}) (time.Time, error) {
		if run == 3 {
			return time.Now(), errors.New("Bad")
		}
		return time.Now().Add(10 * time.Millisecond), nil
	}

	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test job", runtimeFunc, nil, runFunc, nil))
	require.Equal(t, 0, run)
	time.Sleep(time.Duration(50) * time.Millisecond)
	assert.Equal(t, 3, run)
}

func TestDuplicateJobName(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	runtimeFunc := func(ctx context.Context, data interface{}) (time.Time, error) {
		return time.Now().Add(100 * time.Millisecond), nil
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test duplicate job", time.Now().Add(time.Second), runFunc, nil))
	require.EqualError(t, s.ScheduleJob(ctx, "Test", "Test duplicate job", time.Now().Add(time.Second), runFunc, nil), scheduler.ErrJobAlreadyExists.Error())

	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test duplicate periodic job", runtimeFunc, nil, runFunc, nil))
	require.EqualError(t, s.SchedulePeriodicJob(ctx, "Test", "Test duplicate periodic job", runtimeFunc, nil, runFunc, nil), scheduler.ErrJobAlreadyExists.Error())
}

func TestBadJobs(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	runtimeFunc := func(ctx context.Context, data interface{}) (time.Time, error) {
		return time.Now().Add(100 * time.Millisecond), nil
	}

	require.EqualError(t, s.ScheduleJob(ctx, "Test", "", time.Now(), runFunc, nil), scheduler.ErrNoJobName.Error())
	require.EqualError(t, s.ScheduleJob(ctx, "Test", "Test bad job", time.Now(), nil, nil), scheduler.ErrNoJobFunc.Error())

	require.EqualError(t, s.SchedulePeriodicJob(ctx, "Test", "", runtimeFunc, nil, runFunc, nil), scheduler.ErrNoJobName.Error())
	require.EqualError(t, s.SchedulePeriodicJob(ctx, "Test", "Test bad period job", nil, nil, runFunc, nil), scheduler.ErrNoRuntimeFunc.Error())
	require.EqualError(t, s.SchedulePeriodicJob(ctx, "Test", "Test bad period job", runtimeFunc, nil, nil, nil), scheduler.ErrNoJobFunc.Error())
}

func TestManyJobs(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(ctx context.Context, data interface{}) {
		atomic.AddUint32(&run, 1)
	}

	runTime := time.Now().Add(200 * time.Millisecond)

	jobs := 2048
	for i := 0; i < jobs; i++ {
		require.NoError(t, s.ScheduleJob(ctx, "Test", fmt.Sprintf("Job instance %d", i), runTime, runFunc, nil))
	}

	// Kick off some jobs early.
	for i := 0; i < jobs/32; i++ {
		// #nosec G404
		randomJob := rand.Intn(jobs)
		// Don't check for error as we could try to kick off the same job multiple times, which would cause an error.
		//nolint
		s.RunJob(ctx, fmt.Sprintf("Job instance %d", randomJob))
	}

	// Sleep to let the others run normally.
	time.Sleep(400 * time.Millisecond)

	require.Equal(t, uint32(jobs), run)
}

func TestListJobs(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := 0
	runFunc := func(ctx context.Context, data interface{}) {
		run++
	}

	jobs := s.ListJobs(ctx)
	require.Len(t, jobs, 0)

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job 1", time.Now().Add(time.Second), runFunc, nil))

	jobs = s.ListJobs(ctx)
	require.Len(t, jobs, 1)
	require.Contains(t, jobs, "Test job 1")

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job 2", time.Now().Add(time.Second), runFunc, nil))

	jobs = s.ListJobs(ctx)
	require.Len(t, jobs, 2)
	require.Contains(t, jobs, "Test job 1")
	require.Contains(t, jobs, "Test job 2")

	require.NoError(t, s.CancelJob(ctx, "Test job 1"))

	jobs = s.ListJobs(ctx)
	require.Len(t, jobs, 1)
	require.Contains(t, jobs, "Test job 2")
}

func TestLongRunningPeriodicJob(t *testing.T) {
	ctx := context.Background()
	s, err := basic.New(ctx, basic.WithLogLevel(zerolog.Disabled), basic.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	// Job takes 200 ms.
	run := uint32(0)
	jobFunc := func(ctx context.Context, data interface{}) {
		time.Sleep(200 * time.Millisecond)
		atomic.AddUint32(&run, 1)
	}

	// Job runs every 150 ms.
	runtimeFunc := func(ctx context.Context, data interface{}) (time.Time, error) {
		return time.Now().Add(150 * time.Millisecond), nil
	}

	// Schedule the job.
	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test long running periodic job", runtimeFunc, nil, jobFunc, nil))

	// Sleep for 800 ms.  Expect two runs (150+200+150+200+150).
	time.Sleep(800 * time.Millisecond)
	assert.Equal(t, uint32(2), run)
}
