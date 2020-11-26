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
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// SignBeaconAttestations signs multiple beacon attestations.
func (s *Service) SignBeaconAttestations(ctx context.Context,
	accounts []e2wtypes.Account,
	slot spec.Slot,
	committeeIndices []spec.CommitteeIndex,
	blockRoot spec.Root,
	sourceEpoch spec.Epoch,
	sourceRoot spec.Root,
	targetEpoch spec.Epoch,
	targetRoot spec.Root,
) (
	[]spec.BLSSignature,
	error,
) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "signer.SignBeaconAttestations")
	defer span.Finish()

	if len(accounts) == 0 {
		return nil, errors.New("no accounts supplied")
	}

	signatureDomain, err := s.domainProvider.Domain(ctx,
		s.beaconAttesterDomainType,
		spec.Epoch(slot/s.slotsPerEpoch))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for beacon attestation")
	}

	sigs := make([]spec.BLSSignature, len(accounts))
	if multiSigner, isMultiSigner := accounts[0].(e2wtypes.AccountProtectingMultiSigner); isMultiSigner {
		uintCommitteeIndices := make([]uint64, len(committeeIndices))
		for i := range committeeIndices {
			uintCommitteeIndices[i] = uint64(committeeIndices[i])
		}
		signatures, err := multiSigner.SignBeaconAttestations(ctx,
			uint64(slot),
			accounts,
			uintCommitteeIndices,
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
				committeeIndices[i],
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
