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

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// SignBeaconBlockProposal signs a beacon block proposal.
func (s *Service) SignBeaconBlockProposal(ctx context.Context,
	account e2wtypes.Account,
	slot phase0.Slot,
	proposerIndex phase0.ValidatorIndex,
	parentRoot phase0.Root,
	stateRoot phase0.Root,
	bodyRoot phase0.Root,
) (
	phase0.BLSSignature,
	error,
) {

	// Fetch the domain.
	domain, err := s.domainProvider.Domain(ctx,
		s.beaconProposerDomainType,
		phase0.Epoch(slot/s.slotsPerEpoch))
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for beacon proposal")
	}

	var sig phase0.BLSSignature
	if protectingSigner, isProtectingSigner := account.(e2wtypes.AccountProtectingSigner); isProtectingSigner {
		signature, err := protectingSigner.SignBeaconProposal(ctx,
			uint64(slot),
			uint64(proposerIndex),
			parentRoot[:],
			stateRoot[:],
			bodyRoot[:],
			domain[:])
		if err != nil {
			return phase0.BLSSignature{}, errors.Wrap(err, "failed to sign beacon block proposal")
		}
		copy(sig[:], signature.Marshal())
	} else {
		header := &phase0.BeaconBlockHeader{
			Slot:          slot,
			ProposerIndex: proposerIndex,
			ParentRoot:    parentRoot,
			StateRoot:     stateRoot,
			BodyRoot:      bodyRoot,
		}
		root, err := header.HashTreeRoot()
		if err != nil {
			return phase0.BLSSignature{}, errors.Wrap(err, "failed to generate hash tree root")
		}
		sig, err = s.sign(ctx, account, root, domain)
		if err != nil {
			return phase0.BLSSignature{}, err
		}
	}

	return sig, nil
}
