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

package standard

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/pkg/errors"
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
		return nil, errors.New("no execution config at current")
	}
	return s.executionConfig.ProposerConfig(ctx, account, pubkey, s.fallbackFeeRecipient, s.fallbackGasLimit)
}
