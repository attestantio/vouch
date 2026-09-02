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

package standard

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// SignProposerPreferences signs proposer preferences.
func (s *Service) SignProposerPreferences(ctx context.Context,
	account e2wtypes.Account,
	preferences *gloas.ProposerPreferences,
) (
	phase0.BLSSignature,
	error,
) {
	if preferences == nil {
		return phase0.BLSSignature{}, errors.New("no proposer preferences supplied")
	}
	if s.proposerPreferencesDomainType == nil {
		return phase0.BLSSignature{}, errors.New("DOMAIN_PROPOSER_PREFERENCES unavailable in beacon node spec; cannot sign proposer preferences")
	}

	root, err := preferences.HashTreeRoot()
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to calculate proposer preferences hash tree root")
	}
	domain, err := s.domainProvider.Domain(ctx,
		*s.proposerPreferencesDomainType,
		phase0.Epoch(preferences.ProposalSlot/s.slotsPerEpoch))
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for proposer preferences")
	}
	signature, err := s.sign(ctx, account, root, domain)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to sign proposer preferences")
	}

	return signature, nil
}
