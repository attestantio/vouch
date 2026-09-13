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

var builderRequestAuthDomain = phase0.Domain{0x0b, 0x00, 0x00, 0x01}

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
	root, err := auth.HashTreeRoot()
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to calculate builder request authorization hash tree root")
	}
	signature, err := s.sign(ctx, account, root, builderRequestAuthDomain)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to sign builder request authorization")
	}

	return signature, nil
}
