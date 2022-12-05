// Copyright © 2021 Attestant Limited.
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

	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
)

// SignContributionAndProof signs a sync committee contribution for given slot and root.
func (s *Service) SignContributionAndProof(ctx context.Context,
	account e2wtypes.Account,
	contributionAndProof *altair.ContributionAndProof,
) (
	phase0.BLSSignature,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.signer.standard").Start(ctx, "SignContributionAndProof")
	defer span.End()

	if s.contributionAndProofDomainType == nil {
		return phase0.BLSSignature{}, errors.New("no contribution and proof domain type available; cannot sign")
	}

	root, err := contributionAndProof.HashTreeRoot()
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to calculate hash tree root")
	}

	// Calculate the domain.
	epoch := phase0.Epoch(contributionAndProof.Contribution.Slot / s.slotsPerEpoch)
	domain, err := s.domainProvider.Domain(ctx, *s.contributionAndProofDomainType, epoch)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for contribution and proof")
	}

	sig, err := s.sign(ctx, account, root, domain)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to sign contribution and proof")
	}

	return sig, nil
}
