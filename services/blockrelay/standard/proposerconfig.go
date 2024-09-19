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

package standard

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// ProposerConfig returns the proposer configuration for the given validator.
func (s *Service) ProposerConfig(ctx context.Context,
	account e2wtypes.Account,
	pubkey phase0.BLSPubKey,
) (
	*beaconblockproposer.ProposerConfig,
	error,
) {
	s.executionConfigMu.RLock()
	defer s.executionConfigMu.RUnlock()
	if s.executionConfig == nil {
		s.log.Warn().Msg("No execution configuration available; using fallback information")
		return &beaconblockproposer.ProposerConfig{
			FeeRecipient: s.fallbackFeeRecipient,
			Relays:       make([]*beaconblockproposer.RelayConfig, 0),
		}, nil
	}
	return s.executionConfig.ProposerConfig(ctx, account, pubkey, s.fallbackFeeRecipient, s.fallbackGasLimit)
}
