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

package util

import (
	"errors"
	"runtime"
	"sync"
)

// ScatterResult is the result of a single scatter worker.
type ScatterResult struct {
	// Offset is the offset at which the worker started.
	Offset int
	// Extent is the user-defined result of running the scatter function.
	Extent interface{}
}

// Scatter scatters a computation across multiple goroutines, returning a set of per-worker results
func Scatter(inputLen int, concurrency int, work func(int, int, *sync.RWMutex) (interface{}, error)) ([]*ScatterResult, error) {
	if inputLen <= 0 {
		return nil, errors.New("no data with which to work")
	}

	extentSize := calculateExtentSize(inputLen, concurrency)
	workers := inputLen / extentSize
	if inputLen%extentSize != 0 {
		workers++
	}

	resultCh := make(chan *ScatterResult, workers)
	defer close(resultCh)
	errorCh := make(chan error, workers)
	defer close(errorCh)
	mutex := new(sync.RWMutex)
	for worker := 0; worker < workers; worker++ {
		offset := worker * extentSize
		entries := extentSize
		if offset+entries > inputLen {
			entries = inputLen - offset
		}
		go func(offset int, entries int) {
			extent, err := work(offset, entries, mutex)
			if err != nil {
				errorCh <- err
			} else {
				resultCh <- &ScatterResult{
					Offset: offset,
					Extent: extent,
				}
			}
		}(offset, entries)
	}

	// Collect results from workers
	results := make([]*ScatterResult, workers)
	var err error
	for i := 0; i < workers; i++ {
		select {
		case result := <-resultCh:
			results[i] = result
		case err = <-errorCh:
			// Error occurred; don't return because that closes the channels
			// and can cause other workers to write to the closed channel.
		}
	}
	return results, err
}

// calculateExtentSize calculates the extent size given the number of items and maximum processors available.
func calculateExtentSize(items int, desiredConcurrency int) int {
	if desiredConcurrency <= 0 {
		desiredConcurrency = runtime.GOMAXPROCS(0)
	}

	// Start with an even split.
	extentSize := items / desiredConcurrency

	if extentSize == 0 {
		// We must have an extent size of at least 1.
		return 1
	}

	if items%extentSize > 0 {
		// We have a remainder; add one to the extent size to ensure we capture it.
		extentSize++
	}

	return extentSize
}
