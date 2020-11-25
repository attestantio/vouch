// Copyright © 2020 Attestant Limited.
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

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// SignBeaconBlockProposal signs a beacon block proposal item.
func (s *Service) SignBeaconBlockProposal(ctx context.Context,
	account e2wtypes.Account,
	slot spec.Slot,
	proposerIndex spec.ValidatorIndex,
	parentRoot spec.Root,
	stateRoot spec.Root,
	bodyRoot spec.Root,
) (
	spec.BLSSignature,
	error,
) {

	// Fetch the domain.
	domain, err := s.domainProvider.Domain(ctx,
		s.beaconProposerDomainType,
		spec.Epoch(slot/s.slotsPerEpoch))
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for beacon proposal")
	}

	sig, err := account.(e2wtypes.AccountProtectingSigner).SignBeaconProposal(ctx,
		uint64(slot),
		uint64(proposerIndex),
		parentRoot[:],
		stateRoot[:],
		bodyRoot[:],
		domain[:])
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to sign beacon block proposal")
	}

	var signature spec.BLSSignature
	copy(signature[:], sig.Marshal())
	return signature, nil
}
