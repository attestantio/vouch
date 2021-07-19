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

// SignAggregateAndProof signs an aggregate and proof item.
func (s *Service) SignAggregateAndProof(ctx context.Context,
	account e2wtypes.Account,
	slot phase0.Slot,
	aggregateAndProofRoot phase0.Root,
) (
	phase0.BLSSignature,
	error,
) {
	// Fetch the domain.
	domain, err := s.domainProvider.Domain(ctx,
		s.aggregateAndProofDomainType,
		phase0.Epoch(slot/s.slotsPerEpoch))
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for beacon aggregate and proof")
	}

	sig, err := s.sign(ctx, account, aggregateAndProofRoot, domain)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to aggregate and proof")
	}

	return sig, nil
}
