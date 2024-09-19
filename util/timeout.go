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

package util

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Timeout returns the best timeout for the path.
func Timeout(path string) time.Duration {
	if path == "" {
		return viper.GetDuration("timeout")
	}

	key := fmt.Sprintf("%s.timeout", path)
	if viper.GetDuration(key) != 0 {
		return viper.GetDuration(key)
	}
	// Lop off the child and try again.
	lastPeriod := strings.LastIndex(path, ".")
	if lastPeriod == -1 {
		return Timeout("")
	}
	return Timeout(path[0:lastPeriod])
}
