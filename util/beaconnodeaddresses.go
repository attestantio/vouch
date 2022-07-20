// Copyright © 2022 Attestant Limited.
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

// BeaconNodeAddresses returns the best beacon node addresses for the path.
func BeaconNodeAddresses(path string) []string {
	if path == "" {
		if viper.GetStringSlice("beacon-node-addresses") != nil {
			return viper.GetStringSlice("beacon-node-addresses")
		}
		return viper.GetStringSlice("beacon-node-address")
	}

	key := fmt.Sprintf("%s.beacon-node-addresses", path)
	if len(viper.GetStringSlice(key)) > 0 {
		return viper.GetStringSlice(key)
	}
	// Lop off the child and try again.
	lastPeriod := strings.LastIndex(path, ".")
	if lastPeriod == -1 {
		return BeaconNodeAddresses("")
	}
	return BeaconNodeAddresses(path[0:lastPeriod])
}
