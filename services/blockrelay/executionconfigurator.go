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

package blockrelay

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// ExecutionConfigurator is the interface providing proposer configuration information.
type ExecutionConfigurator interface {
	// ProposerConfig returns the proposer configuration for the given validator,
	ProposerConfig(ctx context.Context,
		account e2wtypes.Account,
		pubkey phase0.BLSPubKey,
		fallbackFeeRecipient bellatrix.ExecutionAddress,
		fallbackGasLimit uint64,
	) (
		*beaconblockproposer.ProposerConfig,
		error,
	)
}
