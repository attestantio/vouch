// Copyright © 2026 Attestant Limited.
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
	"regexp"
	"strings"
	"sync"
)

var knownBeaconNodeVersions sync.Map
var safeBeaconNodeVersion = regexp.MustCompile(`(?i)^(lighthouse|lodestar|nimbus|prysm|teku)/v?([0-9]+\.[0-9]+\.[0-9]+)(?:\b|$)`)

type beaconNodeClientDetails struct {
	name    string
	version string
}

// RecordBeaconNodeVersion stores only a recognized client and numeric version for telemetry.
func RecordBeaconNodeVersion(address, version string) {
	matches := safeBeaconNodeVersion.FindStringSubmatch(version)
	if len(matches) == 0 {
		return
	}
	knownBeaconNodeVersions.Store(address, beaconNodeClientDetails{
		name:    strings.ToLower(matches[1]),
		version: matches[2],
	})
}

// BeaconNodeClientDetails returns available client details for a configured node.
func BeaconNodeClientDetails(address string) (string, string) {
	if value, ok := knownBeaconNodeVersions.Load(address); ok {
		details := value.(beaconNodeClientDetails)
		return details.name, details.version
	}
	return "", ""
}
