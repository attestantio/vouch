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

package util

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// ProcessConcurrency returns the best process concurrency for the path.
func ProcessConcurrency(path string) int64 {
	if path == "" {
		return viper.GetInt64("process-concurrency")
	}

	key := fmt.Sprintf("%s.process-concurrency", path)
	if viper.GetString(key) != "" {
		return viper.GetInt64(key)
	}
	// Lop off the child and try again.
	lastPeriod := strings.LastIndex(path, ".")
	if lastPeriod == -1 {
		return ProcessConcurrency("")
	}
	return ProcessConcurrency(path[0:lastPeriod])
}
