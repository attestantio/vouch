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

// SignBeaconAttestation signs a beacon attestation item.
func (s *Service) SignBeaconAttestation(ctx context.Context,
	account e2wtypes.Account,
	slot phase0.Slot,
	committeeIndex phase0.CommitteeIndex,
	blockRoot phase0.Root,
	sourceEpoch phase0.Epoch,
	sourceRoot phase0.Root,
	targetEpoch phase0.Epoch,
	targetRoot phase0.Root,
) (
	phase0.BLSSignature,
	error,
) {
	domain, err := s.domainProvider.Domain(ctx,
		s.beaconAttesterDomainType,
		phase0.Epoch(slot/s.slotsPerEpoch))
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for beacon attestation")
	}

	var sig phase0.BLSSignature
	if protectingSigner, isProtectingSigner := account.(e2wtypes.AccountProtectingSigner); isProtectingSigner {
		signature, err := protectingSigner.SignBeaconAttestation(ctx,
			uint64(slot),
			uint64(committeeIndex),
			blockRoot[:],
			uint64(sourceEpoch),
			sourceRoot[:],
			uint64(targetEpoch),
			targetRoot[:],
			domain[:])
		if err != nil {
			return phase0.BLSSignature{}, errors.Wrap(err, "failed to sign beacon attestation")
		}
		copy(sig[:], signature.Marshal())
	} else {
		attestation := &phase0.AttestationData{
			Slot:            slot,
			Index:           committeeIndex,
			BeaconBlockRoot: blockRoot,
			Source: &phase0.Checkpoint{
				Epoch: sourceEpoch,
				Root:  sourceRoot,
			},
			Target: &phase0.Checkpoint{
				Epoch: targetEpoch,
				Root:  targetRoot,
			},
		}
		root, err := attestation.HashTreeRoot()
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
