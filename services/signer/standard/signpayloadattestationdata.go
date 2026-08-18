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

// SignPayloadAttestationData signs payload attestation data for multiple accounts.
func (s *Service) SignPayloadAttestationData(ctx context.Context,
	accounts []e2wtypes.Account,
	data *gloas.PayloadAttestationData,
) ([]phase0.BLSSignature, error) {
	return s.signPayloadAttestationData(ctx, accounts, data)
}

func (s *Service) signPayloadAttestationData(ctx context.Context,
	accounts []e2wtypes.Account,
	data *gloas.PayloadAttestationData,
) ([]phase0.BLSSignature, error) {
	if len(accounts) == 0 {
		return nil, errors.New("no accounts supplied")
	}
	if data == nil {
		return nil, errors.New("no payload attestation data supplied")
	}
	if s.ptcAttesterDomainType == nil {
		return nil, errors.New("DOMAIN_PTC_ATTESTER unavailable in beacon node spec; cannot sign payload attestation data")
	}

	root, err := data.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to calculate payload attestation data hash tree root")
	}
	domain, err := s.domainProvider.Domain(ctx,
		*s.ptcAttesterDomainType,
		phase0.Epoch(data.Slot/s.slotsPerEpoch))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for payload attestation data")
	}

	roots := make([]phase0.Root, len(accounts))
	for i := range roots {
		roots[i] = root
	}
	sigs, err := s.signRootsByAccountType(ctx, accounts, roots, domain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign payload attestation data")
	}

	return sigs, nil
}
