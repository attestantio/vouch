// Copyright © 2021 - 2024 Attestant Limited.
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

package advanced_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/attestantio/vouch/services/scheduler/advanced"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		options []advanced.Parameter
		err     string
	}{
		{
			name: "Good",
		},
		{
			name: "GoodLogLevel",
			options: []advanced.Parameter{
				advanced.WithLogLevel(zerolog.Disabled),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := advanced.New(ctx, test.options...)
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
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(20*time.Millisecond), runFunc, nil))
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	time.Sleep(time.Duration(50) * time.Millisecond)
	assert.Equal(t, uint32(1), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestJobExists(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(10*time.Second), runFunc, nil))

	require.True(t, s.JobExists(ctx, "Test job"))
	require.False(t, s.JobExists(ctx, "Unknown job"))
	require.Len(t, s.ListJobs(ctx), 1)

	require.NoError(t, s.CancelJob(ctx, "Test job"))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestCancelJob(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(100*time.Millisecond), runFunc, nil))
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 1)
	require.NoError(t, s.CancelJob(ctx, "Test job"))
	require.Len(t, s.ListJobs(ctx), 0)
	time.Sleep(time.Duration(110) * time.Millisecond)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
}

func TestCancelUnknownJob(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	assert.EqualError(t, s.CancelJob(ctx, "Unknown job"), scheduler.ErrNoSuchJob.Error())
}

func TestCancelJobs(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job 1", time.Now().Add(100*time.Millisecond), runFunc, nil))
	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job 2", time.Now().Add(100*time.Millisecond), runFunc, nil))
	require.NoError(t, s.ScheduleJob(ctx, "Test", "No cancel job", time.Now().Add(100*time.Millisecond), runFunc, nil))
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 3)
	s.CancelJobs(ctx, "Test job")
	require.Len(t, s.ListJobs(ctx), 1)
	time.Sleep(time.Duration(110) * time.Millisecond)
	require.Equal(t, uint32(1), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestCancelJobIfExists(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(100*time.Millisecond), runFunc, nil))
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 1)
	s.CancelJobIfExists(ctx, "Test job")
	require.Len(t, s.ListJobs(ctx), 0)
	time.Sleep(time.Duration(110) * time.Millisecond)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))

	s.CancelJobIfExists(ctx, "Unknown job")
}

func TestCancelParentContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(100*time.Millisecond), runFunc, nil))
	require.Len(t, s.ListJobs(ctx), 1)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	cancel()
	time.Sleep(time.Duration(110) * time.Millisecond)
	require.Len(t, s.ListJobs(ctx), 0)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
}

func TestRunJob(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(time.Second), runFunc, nil))
	require.Len(t, s.ListJobs(ctx), 1)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	require.NoError(t, s.RunJob(ctx, "Test job"))
	time.Sleep(time.Duration(100) * time.Millisecond)
	require.Equal(t, uint32(1), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestRunJobIfExists(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(time.Second), runFunc, nil))
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	s.RunJobIfExists(ctx, "Unknown job")
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	s.RunJobIfExists(ctx, "Test job")
	time.Sleep(time.Duration(100) * time.Millisecond)
	require.Equal(t, uint32(1), atomic.LoadUint32(&run))
}

func TestRunUnknownJob(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	assert.EqualError(t, s.RunJob(ctx, "Unknown job"), scheduler.ErrNoSuchJob.Error())
}

func TestPeriodicJob(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	runtimeFunc := func(_ context.Context, _ any) (time.Time, error) {
		return time.Now().Add(100 * time.Millisecond), nil
	}

	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test periodic job", runtimeFunc, nil, runFunc, nil))
	require.Len(t, s.ListJobs(ctx), 1)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	time.Sleep(time.Duration(110) * time.Millisecond)
	require.Equal(t, uint32(1), atomic.LoadUint32(&run))
	time.Sleep(time.Duration(110) * time.Millisecond)
	require.Equal(t, uint32(2), atomic.LoadUint32(&run))
	require.NoError(t, s.RunJob(ctx, "Test periodic job"))
	time.Sleep(time.Duration(10) * time.Millisecond)
	require.Equal(t, uint32(3), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 1)

	require.NoError(t, s.CancelJob(ctx, "Test periodic job"))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestCancelPeriodicJob(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	runtimeFunc := func(_ context.Context, _ any) (time.Time, error) {
		return time.Now().Add(100 * time.Millisecond), nil
	}

	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test periodic job", runtimeFunc, nil, runFunc, nil))
	require.Len(t, s.ListJobs(ctx), 1)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	require.NoError(t, s.CancelJob(ctx, "Test periodic job"))
	time.Sleep(time.Duration(110) * time.Millisecond)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestCancelPeriodicParentContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	runtimeFunc := func(_ context.Context, _ any) (time.Time, error) {
		return time.Now().Add(100 * time.Millisecond), nil
	}

	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test job", runtimeFunc, nil, runFunc, nil))
	require.Len(t, s.ListJobs(ctx), 1)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	cancel()
	time.Sleep(time.Duration(110) * time.Millisecond)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestLimitedPeriodicJob(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	runtimeFunc := func(_ context.Context, _ any) (time.Time, error) {
		if run == 3 {
			return time.Now(), scheduler.ErrNoMoreInstances
		}
		return time.Now().Add(10 * time.Millisecond), nil
	}

	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test job", runtimeFunc, nil, runFunc, nil))
	require.Len(t, s.ListJobs(ctx), 1)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	time.Sleep(time.Duration(50) * time.Millisecond)
	require.Equal(t, uint32(3), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestBadPeriodicJob(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	runtimeFunc := func(_ context.Context, _ any) (time.Time, error) {
		if run == 3 {
			return time.Now(), errors.New("Bad")
		}
		return time.Now().Add(10 * time.Millisecond), nil
	}

	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test job", runtimeFunc, nil, runFunc, nil))
	require.Len(t, s.ListJobs(ctx), 1)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	time.Sleep(time.Duration(50) * time.Millisecond)
	require.Equal(t, uint32(3), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestDuplicateJobName(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	runtimeFunc := func(_ context.Context, _ any) (time.Time, error) {
		return time.Now().Add(100 * time.Millisecond), nil
	}

	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test duplicate job", time.Now().Add(time.Second), runFunc, nil))
	require.Len(t, s.ListJobs(ctx), 1)
	require.EqualError(t, s.ScheduleJob(ctx, "Test", "Test duplicate job", time.Now().Add(time.Second), runFunc, nil), scheduler.ErrJobAlreadyExists.Error())
	require.Len(t, s.ListJobs(ctx), 1)

	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test duplicate periodic job", runtimeFunc, nil, runFunc, nil))
	require.Len(t, s.ListJobs(ctx), 2)
	require.EqualError(t, s.SchedulePeriodicJob(ctx, "Test", "Test duplicate periodic job", runtimeFunc, nil, runFunc, nil), scheduler.ErrJobAlreadyExists.Error())
	require.Len(t, s.ListJobs(ctx), 2)

	require.NoError(t, s.CancelJob(ctx, "Test duplicate job"))
	require.Len(t, s.ListJobs(ctx), 1)
	require.NoError(t, s.CancelJob(ctx, "Test duplicate periodic job"))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestBadJobs(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	runtimeFunc := func(_ context.Context, _ any) (time.Time, error) {
		return time.Now().Add(100 * time.Millisecond), nil
	}

	require.EqualError(t, s.ScheduleJob(ctx, "Test", "", time.Now(), runFunc, nil), scheduler.ErrNoJobName.Error())
	require.Len(t, s.ListJobs(ctx), 0)
	require.EqualError(t, s.ScheduleJob(ctx, "Test", "Test bad job", time.Now(), nil, nil), scheduler.ErrNoJobFunc.Error())
	require.Len(t, s.ListJobs(ctx), 0)

	require.EqualError(t, s.SchedulePeriodicJob(ctx, "Test", "", runtimeFunc, nil, runFunc, nil), scheduler.ErrNoJobName.Error())
	require.Len(t, s.ListJobs(ctx), 0)
	require.EqualError(t, s.SchedulePeriodicJob(ctx, "Test", "Test bad period job", nil, nil, runFunc, nil), scheduler.ErrNoRuntimeFunc.Error())
	require.Len(t, s.ListJobs(ctx), 0)
	require.EqualError(t, s.SchedulePeriodicJob(ctx, "Test", "Test bad period job", runtimeFunc, nil, nil, nil), scheduler.ErrNoJobFunc.Error())
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestManyJobs(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
	}

	runTime := time.Now().Add(200 * time.Millisecond)

	jobs := 2048
	for i := 0; i < jobs; i++ {
		require.NoError(t, s.ScheduleJob(ctx, "Test", fmt.Sprintf("Job instance %d", i), runTime, runFunc, nil))
	}
	require.Len(t, s.ListJobs(ctx), jobs)

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

	require.Equal(t, uint32(jobs), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestListJobs(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
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
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	// Job takes 100 ms.
	run := uint32(0)
	jobFunc := func(_ context.Context, _ any) {
		time.Sleep(100 * time.Millisecond)
		atomic.AddUint32(&run, 1)
	}

	// Job runs every 50 ms.
	runtimeFunc := func(_ context.Context, _ any) (time.Time, error) {
		return time.Now().Add(50 * time.Millisecond), nil
	}

	// Schedule the job.
	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test long running periodic job", runtimeFunc, nil, jobFunc, nil))
	require.Len(t, s.ListJobs(ctx), 1)

	// Sleep for 400 ms.  Expect two runs (50+100+50+100+50).
	time.Sleep(400 * time.Millisecond)
	require.Equal(t, uint32(2), atomic.LoadUint32(&run))

	require.Len(t, s.ListJobs(ctx), 1)
	require.NoError(t, s.CancelJob(ctx, "Test long running periodic job"))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestOverlappingJobs(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	// Job takes 200ms.
	run := uint32(0)
	jobFunc := func(_ context.Context, _ any) {
		time.Sleep(200 * time.Millisecond)
		atomic.AddUint32(&run, 1)
	}

	now := time.Now()
	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job 1", now.Add(100*time.Millisecond), jobFunc, nil))
	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job 2", now.Add(200*time.Millisecond), jobFunc, nil))
	require.Len(t, s.ListJobs(ctx), 2)

	// Sleep to let jobs complete.
	time.Sleep(500 * time.Millisecond)

	// Ensure both jobs have completed.
	require.Equal(t, uint32(2), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestMulti(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	// Create a job for the future.
	run := uint32(0)
	var finishWG sync.WaitGroup
	finishWG.Add(1)
	jobFunc := func(_ context.Context, _ any) {
		atomic.AddUint32(&run, 1)
		finishWG.Done()
	}
	require.NoError(t, s.ScheduleJob(ctx, "Test", "Test job", time.Now().Add(10*time.Second), jobFunc, nil))
	require.Len(t, s.ListJobs(ctx), 1)

	// Create a number of runners that will try to start the job simultaneously.
	var runWG sync.WaitGroup
	var setupWG sync.WaitGroup
	starter := make(chan any)
	for i := 0; i < 32; i++ {
		setupWG.Add(1)
		runWG.Add(1)
		go func() {
			setupWG.Done()
			<-starter
			//nolint
			s.RunJob(ctx, "Test job")
			runWG.Done()
		}()
	}
	// Wait for setup to complete.
	setupWG.Wait()
	// Start the jobs by closing the channel.
	close(starter)

	// Wait for run to complete.
	runWG.Wait()

	// Wait for jobFunc to be called.
	finishWG.Wait()

	// Ensure the job has only completed once.
	require.Equal(t, uint32(1), atomic.LoadUint32(&run))
	require.Len(t, s.ListJobs(ctx), 0)
}

func TestCancelWhilstRunning(t *testing.T) {
	ctx := context.Background()
	s, err := advanced.New(ctx, advanced.WithLogLevel(zerolog.Disabled), advanced.WithMonitor(&nullmetrics.Service{}))
	require.NoError(t, err)
	require.NotNil(t, s)

	run := uint32(0)
	runFunc := func(_ context.Context, _ any) {
		time.Sleep(50 * time.Millisecond)
		atomic.AddUint32(&run, 1)
	}

	runtimeFunc := func(_ context.Context, _ any) (time.Time, error) {
		return time.Now().Add(50 * time.Millisecond), nil
	}

	// Job takes 50 ms and runs every 50ms for a total of 100ms per tick.
	require.NoError(t, s.SchedulePeriodicJob(ctx, "Test", "Test periodic job", runtimeFunc, nil, runFunc, nil))
	require.Len(t, s.ListJobs(ctx), 1)
	require.Contains(t, s.ListJobs(ctx), "Test periodic job")
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	time.Sleep(time.Duration(60) * time.Millisecond)
	require.Equal(t, uint32(0), atomic.LoadUint32(&run))
	// Cancel occurs during first run.
	require.NoError(t, s.CancelJob(ctx, "Test periodic job"))
	require.Len(t, s.ListJobs(ctx), 0)
	// Wait for first run to finish.
	time.Sleep(time.Duration(60) * time.Millisecond)
	require.Equal(t, uint32(1), atomic.LoadUint32(&run))
	// Ensure second run never happens.
	time.Sleep(time.Duration(120) * time.Millisecond)
	require.Equal(t, uint32(1), atomic.LoadUint32(&run))
}
