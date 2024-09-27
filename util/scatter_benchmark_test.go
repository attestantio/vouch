// Copyright © 2024 Attestant Limited.
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
	"crypto/rand"
	"crypto/sha256"
	"runtime"
	"sync"
	"testing"

	"github.com/attestantio/vouch/util"
	"github.com/stretchr/testify/require"
)

var input [][]byte

const (
	benchmarkElements    = 65536
	benchmarkElementSize = 32
	benchmarkHashRuns    = 128
)

func init() {
	input = make([][]byte, benchmarkElements)
	for i := 0; i < benchmarkElements; i++ {
		input[i] = make([]byte, benchmarkElementSize)
		_, err := rand.Read(input[i])
		if err != nil {
			panic(err)
		}
	}
}

// hash is a simple worker function that carries out repeated hashing of its input to provide an output.
func hash(input [][]byte) [][]byte {
	output := make([][]byte, len(input))
	for i := range input {
		copy(output, input)
		for j := 0; j < benchmarkHashRuns; j++ {
			hash := sha256.Sum256(output[i])
			output[i] = hash[:]
		}
	}
	return output
}

func BenchmarkHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		hash(input)
	}
}

func BenchmarkHashMP(b *testing.B) {
	output := make([][]byte, len(input))
	for i := 0; i < b.N; i++ {
		workerResults, err := util.Scatter(len(input), runtime.GOMAXPROCS(0), func(offset int, entries int, _ *sync.RWMutex) (interface{}, error) {
			return hash(input[offset : offset+entries]), nil
		})
		require.NoError(b, err)
		for _, result := range workerResults {
			copy(output[result.Offset:], result.Extent.([][]byte))
		}
	}
}
