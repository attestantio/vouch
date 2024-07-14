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
	"sort"

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
		for _, nodeAddress := range BeaconNodeAddresses("") {
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
	default:
		for _, nodeAddress := range BeaconNodeAddresses("") {
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
