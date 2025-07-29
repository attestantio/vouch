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
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// deduplicationResult holds the result of deduplicating account-root pairs.
type deduplicationResult struct {
	uniqueAccounts        []e2wtypes.Account
	uniqueData            [][]byte
	originalToUniqueIndex []int
}

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

	// Deduplicate (account, root) pairs to avoid duplicate signing requests.
	dedup := deduplicateAccountRootPairs(accounts, data)
	// fmt.Println(fmt.Sprintf("dedupl accounts: %d, real accounts: %d", len(dedup.uniqueAccounts), len(accounts)))
	// for i, acc := range dedup.uniqueAccounts {
	// 	pubKey := phase0.Root(acc.PublicKey().Marshal()).String()
	// 	fmt.Println(fmt.Sprintf("%s,%s,%s,%s", acc.Name(), pubKey, acc.ID().String(), phase0.Root(dedup.uniqueData[i]).String()))
	// }
	if multiSigner, isMultiSigner := accounts[0].(e2wtypes.AccountProtectingMultiSigner); isMultiSigner {
		signatures, err := multiSigner.SignGenericMulti(ctx, dedup.uniqueAccounts, dedup.uniqueData, domain[:])
		if err != nil {
			return []phase0.BLSSignature{}, err
		}
		if err := mapSignaturesToOriginalPositions(sigs, signatures, dedup); err != nil {
			return []phase0.BLSSignature{}, errors.Wrap(err, "failed to map signatures to original positions")
		}
	} else {
		// Sign unique pairs only.
		uniqueSigs := make([]e2types.Signature, len(dedup.uniqueAccounts))
		for i := range dedup.uniqueAccounts {
			container := phase0.SigningData{
				ObjectRoot: phase0.Root(dedup.uniqueData[i]),
				Domain:     domain,
			}
			hashTreeRoot, err := container.HashTreeRoot()
			if err != nil {
				return []phase0.BLSSignature{}, errors.Wrap(err, "failed to generate hash tree root")
			}
			signer, isAccountSigner := dedup.uniqueAccounts[i].(e2wtypes.AccountSigner)
			if !isAccountSigner {
				return []phase0.BLSSignature{}, errors.New("unknown signer type; cannot sign")
			}
			uniqueSigs[i], err = signer.Sign(ctx, hashTreeRoot[:])
			if err != nil {
				return []phase0.BLSSignature{}, err
			}
		}
		if err := mapSignaturesToOriginalPositions(sigs, uniqueSigs, dedup); err != nil {
			return []phase0.BLSSignature{}, errors.Wrap(err, "failed to map signatures to original positions")
		}
	}
	return sigs, nil
}

// signRootsByAccountType collect roots by account type and multi-sign each type.
func (s *Service) signRootsByAccountType(ctx context.Context, accounts []e2wtypes.Account, roots []phase0.Root, domain phase0.Domain) ([]phase0.BLSSignature, error) {
	if len(accounts) != len(roots) {
		return []phase0.BLSSignature{}, errors.New("number of accounts and roots do not match")
	}
	// Need to break the single request in to two: those for accounts and those for distributed accounts.
	// This is because they operate differently (single shot Vs. threshold signing).
	// We also keep a map to allow us to reassemble the signatures in the correct order.
	signingAccountRoots := make([]phase0.Root, 0, len(roots))
	accountSigMap := make(map[int]int)
	signingAccounts := make([]e2wtypes.Account, 0, len(accounts))
	distributedAccountRoots := make([]phase0.Root, 0, len(roots))
	distributedAccountSigMap := make(map[int]int)
	signingDistributedAccounts := make([]e2wtypes.Account, 0, len(accounts))
	for i := range accounts {
		if _, isDistributedAccount := accounts[i].(e2wtypes.DistributedAccount); isDistributedAccount {
			signingDistributedAccounts = append(signingDistributedAccounts, accounts[i])
			distributedAccountSigMap[len(signingDistributedAccounts)-1] = i
			distributedAccountRoots = append(distributedAccountRoots, roots[i])
		} else {
			signingAccounts = append(signingAccounts, accounts[i])
			accountSigMap[len(signingAccounts)-1] = i

			signingAccountRoots = append(signingAccountRoots, roots[i])
		}
	}

	// Because this function returns all or none of the signatures we run these in series.  This ensures that we don't
	// end up in a situation where one Vouch instance obtains signatures for individual accounts and the other for distributed accounts,
	// which would result in neither of them returning the full set of signatures and hence both erroring out.
	sigs := make([]phase0.BLSSignature, len(accounts))
	if len(signingAccounts) > 0 {
		signatures, err := s.signRootsMulti(ctx, signingAccounts, signingAccountRoots, domain)
		if err != nil {
			return nil, errors.Wrap(err, "failed to sign for individual accounts")
		}
		for i := range signatures {
			sigs[accountSigMap[i]] = signatures[i]
		}
	}
	if len(signingDistributedAccounts) > 0 {
		signatures, err := s.signRootsMulti(ctx, signingDistributedAccounts, distributedAccountRoots, domain)
		if err != nil {
			return nil, errors.Wrap(err, "failed to sign for distributed accounts")
		}
		for i := range signatures {
			sigs[distributedAccountSigMap[i]] = signatures[i]
		}
	}
	return sigs, nil
}

// deduplicateAccountRootPairs deduplicates (account, root) pairs to avoid duplicate signing requests.
// It returns unique accounts and data along with a mapping from original indices to unique indices.
func deduplicateAccountRootPairs(accounts []e2wtypes.Account, data [][]byte) deduplicationResult {
	// Map to first occurrence index.
	uniquePairs := make(map[string]int)
	var uniqueAccounts []e2wtypes.Account
	var uniqueData [][]byte
	originalToUniqueIndex := make([]int, len(accounts))

	for i := range accounts {
		accountKey := accounts[i].Name() // + phase0.Root(data[i]).String()

		if uniqueIndex, exists := uniquePairs[accountKey]; exists {
			originalToUniqueIndex[i] = uniqueIndex
		} else {
			uniqueIndex = len(uniqueAccounts)
			uniquePairs[accountKey] = uniqueIndex
			originalToUniqueIndex[i] = uniqueIndex
			uniqueAccounts = append(uniqueAccounts, accounts[i])
			uniqueData = append(uniqueData, data[i])
		}
	}

	return deduplicationResult{
		uniqueAccounts:        uniqueAccounts,
		uniqueData:            uniqueData,
		originalToUniqueIndex: originalToUniqueIndex,
	}
}

// mapSignaturesToOriginalPositions maps unique signatures back to the original request positions.
func mapSignaturesToOriginalPositions(
	sigs []phase0.BLSSignature,
	uniqueSigs []e2types.Signature,
	dedup deduplicationResult,
) error {
	for i := range sigs {
		uniqueIndex := dedup.originalToUniqueIndex[i]
		if uniqueIndex >= len(uniqueSigs) {
			return errors.New("unique index out of bounds")
		}
		if uniqueSigs[uniqueIndex] == nil {
			return errors.New("signature is nil")
		}
		copy(sigs[i][:], uniqueSigs[uniqueIndex].Marshal())
	}
	return nil
}
