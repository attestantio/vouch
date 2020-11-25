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
	"encoding/binary"

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// SignRANDAOReveal returns a RANDAO reveal signature.
// This signs an epoch with the "RANDAO reveal" domain.
func (s *Service) SignRANDAOReveal(ctx context.Context,
	account e2wtypes.Account,
	slot spec.Slot,
) (
	spec.BLSSignature,
	error,
) {
	var messageRoot spec.Root
	epoch := spec.Epoch(slot / s.slotsPerEpoch)
	binary.LittleEndian.PutUint64(messageRoot[:], uint64(epoch))

	// Obtain the RANDAO reveal signature domain.
	domain, err := s.domainProvider.Domain(ctx,
		s.randaoDomainType,
		epoch)
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for RANDAO reveal")
	}

	epochBytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(epochBytes, uint64(epoch))

	sig, err := account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx, epochBytes, domain[:])
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to sign RANDO reveal")
	}

	var signature spec.BLSSignature
	copy(signature[:], sig.Marshal())
	return signature, nil
}
