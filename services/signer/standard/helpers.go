// Copyright © 2024 Attestant Limited.
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
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// sign signs a root, using protected methods if possible.
func (*Service) sign(ctx context.Context,
	account e2wtypes.Account,
	root phase0.Root,
	domain phase0.Domain,
) (
	phase0.BLSSignature,
	error,
) {
	if account == nil {
		return phase0.BLSSignature{}, errors.New("account is nil; cannot sign")
	}
	var sig e2types.Signature
	if protectingSigner, isProtectingSigner := account.(e2wtypes.AccountProtectingSigner); isProtectingSigner {
		var err error
		sig, err = protectingSigner.SignGeneric(ctx, root[:], domain[:])
		if err != nil {
			return phase0.BLSSignature{}, err
		}
	} else {
		container := phase0.SigningData{
			ObjectRoot: root,
			Domain:     domain,
		}
		root, err := container.HashTreeRoot()
		if err != nil {
			return phase0.BLSSignature{}, errors.Wrap(err, "failed to generate hash tree root")
		}
		sig, err = account.(e2wtypes.AccountSigner).Sign(ctx, root[:])
		if err != nil {
			return phase0.BLSSignature{}, err
		}
	}

	var signature phase0.BLSSignature
	copy(signature[:], sig.Marshal())
	return signature, nil
}

// signRootMulti signs the same root for multiple accounts, using protected methods if possible.
func (s *Service) signRootMulti(ctx context.Context,
	accounts []e2wtypes.Account,
	root phase0.Root,
	domain phase0.Domain,
) (
	[]phase0.BLSSignature,
	error,
) {
	roots := make([]phase0.Root, len(accounts))
	for i := range accounts {
		roots[i] = root
	}
	return s.signRootsMulti(ctx, accounts, roots, domain)
}

// signRootsMulti signs multiple roots for multiple accounts, using protected methods if possible.
func (*Service) signRootsMulti(ctx context.Context,
	accounts []e2wtypes.Account,
	roots []phase0.Root,
	domain phase0.Domain,
) (
	[]phase0.BLSSignature,
	error,
) {
	if len(accounts) == 0 {
		return []phase0.BLSSignature{}, errors.New("no accounts; cannot sign")
	}
	sigs := make([]phase0.BLSSignature, len(accounts))
	data := make([][]byte, len(roots))
	for i := range roots {
		data[i] = roots[i][:]
	}

	if multiSigner, isMultiSigner := accounts[0].(e2wtypes.AccountProtectingMultiSigner); isMultiSigner {
		var err error
		signatures, err := multiSigner.SignGenericMulti(ctx, accounts, data, domain[:])
		if err != nil {
			return []phase0.BLSSignature{}, err
		}
		for i := range signatures {
			if signatures[i] != nil {
				copy(sigs[i][:], signatures[i].Marshal())
			}
		}
	} else {
		for i := range accounts {
			container := phase0.SigningData{
				ObjectRoot: roots[i],
				Domain:     domain,
			}
			hashTreeRoot, err := container.HashTreeRoot()
			if err != nil {
				return []phase0.BLSSignature{}, errors.Wrap(err, "failed to generate hash tree root")
			}
			signer, isAccountSigner := accounts[i].(e2wtypes.AccountSigner)
			if !isAccountSigner {
				return []phase0.BLSSignature{}, errors.New("unknown signer type; cannot sign")
			}
			sig, err := signer.Sign(ctx, hashTreeRoot[:])
			if err != nil {
				return []phase0.BLSSignature{}, err
			}
			copy(sigs[i][:], sig.Marshal())
		}
	}
	return sigs, nil
}
