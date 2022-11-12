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
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"testing"

	"github.com/attestantio/dirk/util"
	log "github.com/sirupsen/logrus"
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
			log.WithError(err).Debug("Cannot read from rand")
		}
	}
}

// hash is a simple worker function that carries out repeated hashging of its input to provide an output.
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
		workerResults, err := util.Scatter(len(input), func(offset int, entries int, _ *sync.RWMutex) (interface{}, error) {
			return hash(input[offset : offset+entries]), nil
		})
		require.NoError(b, err)
		for _, result := range workerResults {
			copy(output[result.Offset:], result.Extent.([][]byte))
		}
	}
}
