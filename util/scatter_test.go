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

package util_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/attestantio/dirk/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDouble(t *testing.T) {
	tests := []struct {
		name     string
		inValues int
		err      string
	}{
		{
			name:     "0",
			inValues: 0,
			err:      "no data with which to work",
		},
		{
			name:     "1",
			inValues: 1,
		},
		{
			name:     "1023",
			inValues: 1023,
		},
		{
			name:     "1024",
			inValues: 1024,
		},
		{
			name:     "1025",
			inValues: 1025,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inValues := make([]int, test.inValues)
			for i := 0; i < test.inValues; i++ {
				inValues[i] = i
			}
			outValues := make([]int, test.inValues)
			workerResults, err := util.Scatter(len(inValues), func(offset int, entries int, _ *sync.RWMutex) (interface{}, error) {
				extent := make([]int, entries)
				for i := 0; i < entries; i++ {
					extent[i] = inValues[offset+i] * 2
				}
				return extent, nil
			})
			if test.err != "" {
				assert.Equal(t, test.err, err.Error())
			} else {
				require.NoError(t, err)
				for _, result := range workerResults {
					copy(outValues[result.Offset:], result.Extent.([]int))
				}

				for i := 0; i < test.inValues; i++ {
					require.Equal(t, inValues[i]*2, outValues[i], "Outvalue at %d incorrect", i)
				}
			}
		})
	}
}

func TestMutex(t *testing.T) {
	totalRuns := 1048576
	val := 0
	_, err := util.Scatter(totalRuns, func(offset int, entries int, mu *sync.RWMutex) (interface{}, error) {
		for i := 0; i < entries; i++ {
			mu.Lock()
			val++
			mu.Unlock()
		}
		return nil, nil
	})
	require.NoError(t, err)
	require.Equal(t, totalRuns, val)
}

func TestError(t *testing.T) {
	totalRuns := 1024
	val := 0
	_, err := util.Scatter(totalRuns, func(offset int, entries int, mu *sync.RWMutex) (interface{}, error) {
		for i := 0; i < entries; i++ {
			mu.Lock()
			val++
			if val == 1011 {
				mu.Unlock()
				return nil, errors.New("bad number")
			}
			mu.Unlock()
		}
		return nil, nil
	})
	require.EqualError(t, err, "bad number")
}
