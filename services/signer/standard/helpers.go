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
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// sign signs a root, using protected methods if possible.
func (s *Service) sign(ctx context.Context,
	account e2wtypes.Account,
	root spec.Root,
	domain spec.Domain,
) (
	spec.BLSSignature,
	error,
) {
	var sig e2types.Signature
	if protectingSigner, isProtectingSigner := account.(e2wtypes.AccountProtectingSigner); isProtectingSigner {
		var err error
		sig, err = protectingSigner.SignGeneric(ctx, root[:], domain[:])
		if err != nil {
			return spec.BLSSignature{}, err
		}
	} else {
		container := spec.SigningData{
			ObjectRoot: root,
			Domain:     domain,
		}
		root, err := container.HashTreeRoot()
		if err != nil {
			return spec.BLSSignature{}, errors.Wrap(err, "failed to generate hash tree root")
		}
		sig, err = account.(e2wtypes.AccountSigner).Sign(ctx, root[:])
		if err != nil {
			return spec.BLSSignature{}, err
		}
	}

	var signature spec.BLSSignature
	copy(signature[:], sig.Marshal())
	return signature, nil
}
