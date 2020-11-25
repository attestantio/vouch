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

// SignBeaconAttestation signs a beacon attestation item.
func (s *Service) SignBeaconAttestation(ctx context.Context,
	account e2wtypes.Account,
	slot spec.Slot,
	committeeIndex spec.CommitteeIndex,
	blockRoot spec.Root,
	sourceEpoch spec.Epoch,
	sourceRoot spec.Root,
	targetEpoch spec.Epoch,
	targetRoot spec.Root,
) (
	spec.BLSSignature,
	error,
) {

	domain, err := s.domainProvider.Domain(ctx,
		s.beaconAttesterDomainType,
		spec.Epoch(slot/s.slotsPerEpoch))
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for beacon attestation")
	}

	sig, err := account.(e2wtypes.AccountProtectingSigner).SignBeaconAttestation(ctx,
		uint64(slot),
		uint64(committeeIndex),
		blockRoot[:],
		uint64(sourceEpoch),
		sourceRoot[:],
		uint64(targetEpoch),
		targetRoot[:],
		domain[:])
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to sign beacon attestation")
	}

	var signature spec.BLSSignature
	copy(signature[:], sig.Marshal())
	return signature, nil
}
