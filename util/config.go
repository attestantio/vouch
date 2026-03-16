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
	"sort"
	"strings"

	"github.com/spf13/viper"
)

// BeaconNodeAddressesForProposing obtains the beacon node addresses used for
// proposing from the configuration.
// This takes into account the used styles in strategies, and removes duplicates.
func BeaconNodeAddressesForProposing() []string {
	nodeAddresses := make(map[string]struct{})
	switch viper.GetString("strategies.beaconblockproposal.style") {
	case "best":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.beaconblockproposal.best") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	case "first":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.beaconblockproposal.first") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	default:
		for _, nodeAddress := range BeaconNodeAddresses("strategies.beaconblockproposal") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	}

	switch viper.GetString("strategies.blindedbeaconblockproposal.style") {
	case "best":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.blindedbeaconblockproposal.best") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	case "first":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.blindedbeaconblockproposal.first") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	default:
		for _, nodeAddress := range BeaconNodeAddresses("strategies.blindedbeaconblockproposal") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	}

	addresses := make([]string, 0, len(nodeAddresses))
	for nodeAddress := range nodeAddresses {
		addresses = append(addresses, nodeAddress)
	}
	sort.Strings(addresses)

	return addresses
}

// BeaconNodeAddressesForAttesting obtains the beacon node addresses used for
// attesting from the configuration.
// This takes into account the used styles in strategies, and removes duplicates.
func BeaconNodeAddressesForAttesting() []string {
	nodeAddresses := make(map[string]struct{})
	switch viper.GetString("strategies.attestationdata.style") {
	case "best":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.attestationdata.best") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	case "first":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.attestationdata.first") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	case "majority":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.attestationdata.majority") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	case "combinedmajority":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.attestationdata.combinedmajority") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	default:
		for _, nodeAddress := range BeaconNodeAddresses("strategies.attestationdata") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	}

	addresses := make([]string, 0, len(nodeAddresses))
	for nodeAddress := range nodeAddresses {
		addresses = append(addresses, nodeAddress)
	}
	sort.Strings(addresses)

	return addresses
}

// BeaconNodeAddressesForAggregateAttestations obtains the beacon node addresses used for
// aggregate attestations from the configuration.
// This takes into account the used styles in strategies, and removes duplicates.
func BeaconNodeAddressesForAggregateAttestations() []string {
	nodeAddresses := make(map[string]struct{})
	switch viper.GetString("strategies.aggregateattestation.style") {
	case "best":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.aggregateattestation.best") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	case "first":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.aggregateattestation.first") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	default:
		for _, nodeAddress := range BeaconNodeAddresses("strategies.aggregateattestation") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	}

	addresses := make([]string, 0, len(nodeAddresses))
	for nodeAddress := range nodeAddresses {
		addresses = append(addresses, nodeAddress)
	}
	sort.Strings(addresses)

	return addresses
}

func BeaconNodeAddressesForBeaconBlockRoots() []string {
	nodeAddresses := make(map[string]struct{})
	switch viper.GetString("strategies.beaconblockroot.style") {
	case "majority":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.beaconblockroot.majority") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	case "first":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.beaconblockroot.first") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	case "latest":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.beaconblockroot.latest") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	default:
		for _, nodeAddress := range BeaconNodeAddresses("strategies.beaconblockroot") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	}

	addresses := make([]string, 0, len(nodeAddresses))
	for nodeAddress := range nodeAddresses {
		addresses = append(addresses, nodeAddress)
	}
	sort.Strings(addresses)

	return addresses
}

func BeaconNodeAddressesForSyncCommitteeContributions() []string {
	nodeAddresses := make(map[string]struct{})
	switch viper.GetString("strategies.synccommitteecontribution.style") {
	case "best":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.synccommitteecontribution.best") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	case "first":
		for _, nodeAddress := range BeaconNodeAddresses("strategies.synccommitteecontribution.first") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	default:
		for _, nodeAddress := range BeaconNodeAddresses("strategies.synccommitteecontribution") {
			nodeAddresses[nodeAddress] = struct{}{}
		}
	}

	addresses := make([]string, 0, len(nodeAddresses))
	for nodeAddress := range nodeAddresses {
		addresses = append(addresses, nodeAddress)
	}
	sort.Strings(addresses)

	return addresses
}

// HierarchicalBool returns the best configuration value for the path.
func HierarchicalBool(variable string, path string) bool {
	if path == "" {
		return viper.GetBool(variable)
	}

	key := fmt.Sprintf("%s.%s", path, variable)
	if viper.GetString(key) != "" {
		return viper.GetBool(key)
	}
	// Lop off the child and try again.
	lastPeriod := strings.LastIndex(path, ".")
	if lastPeriod == -1 {
		return HierarchicalBool(variable, "")
	}
	return HierarchicalBool(variable, path[0:lastPeriod])
}
