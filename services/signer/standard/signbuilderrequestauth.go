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

// builderRequestAuthDomainType is DOMAIN_BUILDER_REQUEST_AUTH from the builder specs.  Beacon
// nodes do not publish it in their spec.
var builderRequestAuthDomainType = phase0.DomainType{0x0b, 0x00, 0x00, 0x01}

// builderRequestAuthDomain returns compute_domain(DOMAIN_BUILDER_REQUEST_AUTH): the genesis fork
// version with a zero genesis validators root.  go-eth2-client's GenesisDomain uses the zero root
// only for DOMAIN_APPLICATION_BUILDER, so it cannot be used here.  It returns nil if the spec has
// no genesis fork version.
func builderRequestAuthDomain(spec map[string]any) *phase0.Domain {
	version, ok := spec["GENESIS_FORK_VERSION"].(phase0.Version)
	if !ok {
		return nil
	}
	root, err := (&phase0.ForkData{CurrentVersion: version}).HashTreeRoot()
	if err != nil {
		return nil
	}
	var domain phase0.Domain
	copy(domain[:], builderRequestAuthDomainType[:])
	copy(domain[4:], root[:])

	return &domain
}

// SignBuilderRequestAuth signs direct-builder request authorization.
func (s *Service) SignBuilderRequestAuth(ctx context.Context,
	account e2wtypes.Account,
	auth *gloas.BuilderRequestAuth,
) (
	phase0.BLSSignature,
	error,
) {
	if auth == nil {
		return phase0.BLSSignature{}, errors.New("no builder request authorization supplied")
	}
	if s.builderRequestAuthDomain == nil {
		return phase0.BLSSignature{}, errors.New("no builder request authorization domain available; cannot sign")
	}
	root, err := auth.HashTreeRoot()
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to calculate builder request authorization hash tree root")
	}
	signature, err := s.sign(ctx, account, root, *s.builderRequestAuthDomain)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to sign builder request authorization")
	}

	return signature, nil
}
