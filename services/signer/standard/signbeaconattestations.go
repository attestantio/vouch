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
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// SignBeaconAttestations signs multiple beacon attestations.
func (s *Service) SignBeaconAttestations(ctx context.Context,
	accounts []e2wtypes.Account,
	slot phase0.Slot,
	committeeIndices []phase0.CommitteeIndex,
	blockRoot phase0.Root,
	sourceEpoch phase0.Epoch,
	sourceRoot phase0.Root,
	targetEpoch phase0.Epoch,
	targetRoot phase0.Root,
) (
	[]phase0.BLSSignature,
	error,
) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "signer.SignBeaconAttestations")
	defer span.Finish()

	if len(accounts) == 0 {
		return nil, errors.New("no accounts supplied")
	}

	signatureDomain, err := s.domainProvider.Domain(ctx,
		s.beaconAttesterDomainType,
		phase0.Epoch(slot/s.slotsPerEpoch))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for beacon attestation")
	}

	// Need to break the single request in to two: those for accounts and those for distributed accounts.
	// This is because they operate differently (single shot Vs. threshold signing).
	// We also keep a map to allow us to reassemble the signatures in the correct order.
	accountCommitteeIndices := make([]uint64, 0, len(committeeIndices))
	accountSigMap := make(map[int]int)
	signingAccounts := make([]e2wtypes.Account, 0, len(accounts))
	distributedAccountCommitteeIndices := make([]uint64, 0, len(committeeIndices))
	distributedAccountSigMap := make(map[int]int)
	signingDistributedAccounts := make([]e2wtypes.Account, 0, len(accounts))
	for i := range accounts {
		if _, isDistributedAccount := accounts[i].(e2wtypes.DistributedAccount); isDistributedAccount {
			signingDistributedAccounts = append(signingDistributedAccounts, accounts[i])
			distributedAccountSigMap[len(signingDistributedAccounts)-1] = i
			distributedAccountCommitteeIndices = append(distributedAccountCommitteeIndices, uint64(committeeIndices[i]))
		} else {
			signingAccounts = append(signingAccounts, accounts[i])
			accountSigMap[len(signingAccounts)-1] = i
			accountCommitteeIndices = append(accountCommitteeIndices, uint64(committeeIndices[i]))
		}
	}

	sigs := make([]phase0.BLSSignature, len(accounts))
	if len(signingAccounts) > 0 {
		signatures, err := s.signBeaconAttestations(ctx, signingAccounts, slot, accountCommitteeIndices, blockRoot, sourceEpoch, sourceRoot, targetEpoch, targetRoot, signatureDomain)
		if err != nil {
			return nil, err
		}
		for i := range signatures {
			sigs[accountSigMap[i]] = signatures[i]
		}
	}
	if len(signingDistributedAccounts) > 0 {
		signatures, err := s.signBeaconAttestations(ctx, signingDistributedAccounts, slot, distributedAccountCommitteeIndices, blockRoot, sourceEpoch, sourceRoot, targetEpoch, targetRoot, signatureDomain)
		if err != nil {
			return nil, err
		}
		for i := range signatures {
			sigs[distributedAccountSigMap[i]] = signatures[i]
		}
	}

	return sigs, nil
}

func (s *Service) signBeaconAttestations(ctx context.Context,
	accounts []e2wtypes.Account,
	slot phase0.Slot,
	committeeIndices []uint64,
	blockRoot phase0.Root,
	sourceEpoch phase0.Epoch,
	sourceRoot phase0.Root,
	targetEpoch phase0.Epoch,
	targetRoot phase0.Root,
	signatureDomain phase0.Domain,
) ([]phase0.BLSSignature, error) {
	var err error
	sigs := make([]phase0.BLSSignature, len(accounts))

	if len(accounts) == 0 {
		return sigs, nil
	}

	if multiSigner, isMultiSigner := accounts[0].(e2wtypes.AccountProtectingMultiSigner); isMultiSigner {
		signatures, err := multiSigner.SignBeaconAttestations(ctx,
			uint64(slot),
			accounts,
			committeeIndices,
			blockRoot[:],
			uint64(sourceEpoch),
			sourceRoot[:],
			uint64(targetEpoch),
			targetRoot[:],
			signatureDomain[:],
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to multisign beacon attestation")
		}
		for i := range signatures {
			if signatures[i] != nil {
				copy(sigs[i][:], signatures[i].Marshal())
			}
		}
	} else {
		for i := range accounts {
			sigs[i], err = s.SignBeaconAttestation(ctx,
				accounts[i],
				slot,
				phase0.CommitteeIndex(committeeIndices[i]),
				blockRoot,
				sourceEpoch,
				sourceRoot,
				targetEpoch,
				targetRoot,
			)
			if err != nil {
				return nil, errors.Wrap(err, "failed to sign beacon attestation")
			}
		}
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign beacon attestation")
	}

	return sigs, nil
}
