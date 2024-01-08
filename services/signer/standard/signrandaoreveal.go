// Copyright © 2020, 2024 Attestant Limited.
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

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
)

// SignRANDAOReveal returns a RANDAO reveal signature.
// This signs an epoch with the "RANDAO reveal" domain.
func (s *Service) SignRANDAOReveal(ctx context.Context,
	account e2wtypes.Account,
	slot phase0.Slot,
) (
	phase0.BLSSignature,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.signer.standard").Start(ctx, "SignRANDAOReveal")
	defer span.End()

	var messageRoot phase0.Root
	epoch := phase0.Epoch(slot / s.slotsPerEpoch)
	binary.LittleEndian.PutUint64(messageRoot[:], uint64(epoch))

	// Obtain the RANDAO reveal signature domain.
	domain, err := s.domainProvider.Domain(ctx,
		s.randaoDomainType,
		epoch)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for RANDAO reveal")
	}

	var epochBytes phase0.Root
	binary.LittleEndian.PutUint64(epochBytes[:], uint64(epoch))

	sig, err := s.sign(ctx, account, epochBytes, domain)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to sign RANDAO reveal")
	}

	return sig, nil
}
