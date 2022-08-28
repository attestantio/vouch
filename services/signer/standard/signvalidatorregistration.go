// Copyright © 2022 Attestant Limited.
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
	"fmt"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// SignValidatorRegistration signs a validator registration.
func (s *Service) SignValidatorRegistration(ctx context.Context,
	account e2wtypes.Account,
	registration *api.VersionedValidatorRegistration,
) (
	phase0.BLSSignature,
	error,
) {
	if registration == nil {
		return phase0.BLSSignature{}, errors.New("no registration supplied")
	}

	if s.applicationBuilderDomainType == nil {
		return phase0.BLSSignature{}, errors.New("no application builder domain type available; cannot sign")
	}

	var root phase0.Root
	var err error
	switch registration.Version {
	case spec.BuilderVersionV1:
		if registration.V1 == nil {
			return phase0.BLSSignature{}, errors.New("no V1 registration supplied")
		}
		root, err = registration.V1.HashTreeRoot()
	default:
		return phase0.BLSSignature{}, fmt.Errorf("unsupported registration version %v", registration.Version)
	}
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to calculate hash tree root")
	}

	// Calculate the domain.
	domain, err := s.domainProvider.Domain(ctx, *s.applicationBuilderDomainType, 0)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for builder")
	}

	sig, err := s.sign(ctx, account, root, domain)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to sign builder")
	}

	return sig, nil
}
