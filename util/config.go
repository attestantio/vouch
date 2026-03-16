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

// uniqueSortedAddresses deduplicates and sorts the given address slices.
func uniqueSortedAddresses(addressSlices ...[]string) []string {
	nodeAddresses := make(map[string]struct{})
	for _, addresses := range addressSlices {
		for _, address := range addresses {
			nodeAddresses[address] = struct{}{}
		}
	}

	result := make([]string, 0, len(nodeAddresses))
	for address := range nodeAddresses {
		result = append(result, address)
	}
	sort.Strings(result)

	return result
}

// BeaconNodeAddressesForBeaconBlockProposal obtains the beacon node addresses
// used for beacon block proposals from the configuration.
// This takes into account the used styles in strategies, and removes duplicates.
func BeaconNodeAddressesForBeaconBlockProposal() []string {
	switch viper.GetString("strategies.beaconblockproposal.style") {
	case "best":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.beaconblockproposal.best"))
	case "first":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.beaconblockproposal.first"))
	default:
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.beaconblockproposal"))
	}
}

// beaconNodeAddressesForBlindedBeaconBlockProposal obtains the beacon node addresses
// used for blinded beacon block proposals from the configuration.
func beaconNodeAddressesForBlindedBeaconBlockProposal() []string {
	switch viper.GetString("strategies.blindedbeaconblockproposal.style") {
	case "best":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.blindedbeaconblockproposal.best"))
	case "first":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.blindedbeaconblockproposal.first"))
	default:
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.blindedbeaconblockproposal"))
	}
}

// BeaconNodeAddressesForProposing obtains the beacon node addresses used for
// proposing from the configuration.
// This takes into account the used styles in strategies, and removes duplicates.
func BeaconNodeAddressesForProposing() []string {
	return uniqueSortedAddresses(
		BeaconNodeAddressesForBeaconBlockProposal(),
		beaconNodeAddressesForBlindedBeaconBlockProposal(),
	)
}

// BeaconNodeAddressesForAttesting obtains the beacon node addresses used for
// attesting from the configuration.
// This takes into account the used styles in strategies, and removes duplicates.
func BeaconNodeAddressesForAttesting() []string {
	switch viper.GetString("strategies.attestationdata.style") {
	case "best":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.attestationdata.best"))
	case "first":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.attestationdata.first"))
	case "majority":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.attestationdata.majority"))
	case "combinedmajority":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.attestationdata.combinedmajority"))
	default:
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.attestationdata"))
	}
}

// BeaconNodeAddressesForAggregateAttestations obtains the beacon node addresses used for
// aggregate attestations from the configuration.
// This takes into account the used styles in strategies, and removes duplicates.
func BeaconNodeAddressesForAggregateAttestations() []string {
	switch viper.GetString("strategies.aggregateattestation.style") {
	case "best":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.aggregateattestation.best"))
	case "first":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.aggregateattestation.first"))
	default:
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.aggregateattestation"))
	}
}

// BeaconNodeAddressesForBeaconBlockRoots obtains the beacon node addresses used for
// beacon block roots from the configuration.
// This takes into account the used styles in strategies, and removes duplicates.
func BeaconNodeAddressesForBeaconBlockRoots() []string {
	switch viper.GetString("strategies.beaconblockroot.style") {
	case "majority":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.beaconblockroot.majority"))
	case "first":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.beaconblockroot.first"))
	case "latest":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.beaconblockroot.latest"))
	default:
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.beaconblockroot"))
	}
}

// BeaconNodeAddressesForSyncCommitteeContributions obtains the beacon node addresses used for
// sync committee contributions from the configuration.
// This takes into account the used styles in strategies, and removes duplicates.
func BeaconNodeAddressesForSyncCommitteeContributions() []string {
	switch viper.GetString("strategies.synccommitteecontribution.style") {
	case "best":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.synccommitteecontribution.best"))
	case "first":
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.synccommitteecontribution.first"))
	default:
		return uniqueSortedAddresses(BeaconNodeAddresses("strategies.synccommitteecontribution"))
	}
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
