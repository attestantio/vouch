// Copyright © 2020 - 2026 Attestant Limited.
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
	"github.com/google/uuid"
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

// dedupKey identifies a unique (account, root) pair for deduplication.
type dedupKey struct {
	accountID uuid.UUID
	root      phase0.Root
}

// signRootsMulti signs multiple roots for multiple accounts, using protected methods if possible.
// Duplicate (account, root) pairs are deduplicated so that signing is only performed once per unique pair.
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
	if len(accounts) != len(roots) {
		return []phase0.BLSSignature{}, errors.New("number of accounts and roots do not match")
	}

	// Deduplicate (account, root) pairs.
	uniqueMap := make(map[dedupKey]int, len(accounts))
	indexMapping := make([]int, len(accounts))
	uniqueAccounts := make([]e2wtypes.Account, 0, len(accounts))
	uniqueRoots := make([]phase0.Root, 0, len(accounts))
	for i, acct := range accounts {
		key := dedupKey{accountID: acct.ID(), root: roots[i]}
		if idx, exists := uniqueMap[key]; exists {
			indexMapping[i] = idx
		} else {
			uniqueMap[key] = len(uniqueAccounts)
			indexMapping[i] = len(uniqueAccounts)
			uniqueAccounts = append(uniqueAccounts, acct)
			uniqueRoots = append(uniqueRoots, roots[i])
		}
	}

	uniqueData := make([][]byte, len(uniqueRoots))
	for i := range uniqueRoots {
		uniqueData[i] = uniqueRoots[i][:]
	}

	uniqueSigs := make([]phase0.BLSSignature, len(uniqueAccounts))

	// All accounts are homogeneous (same signer type) — enforced upstream by signRootsByAccountType.
	if multiSigner, isMultiSigner := uniqueAccounts[0].(e2wtypes.AccountProtectingMultiSigner); isMultiSigner {
		// Split into batches where each batch contains at most one entry per account.
		// Dirk rejects Multisign batches with duplicate pubkeys, even with different signing roots.
		// Single pass: count occurrences per account and determine number of batches needed.
		accountOccurrences := make(map[uuid.UUID]int, len(uniqueAccounts))
		numBatches := 0
		for _, acct := range uniqueAccounts {
			id := acct.ID()
			next := accountOccurrences[id]
			accountOccurrences[id] = next + 1
			if next+1 > numBatches {
				numBatches = next + 1
			}
		}

		if numBatches == 1 {
			// Fast path: all accounts are unique, single batch.
			signatures, err := multiSigner.SignGenericMulti(ctx, uniqueAccounts, uniqueData, domain[:])
			if err != nil {
				return []phase0.BLSSignature{}, err
			}
			for i := range signatures {
				if signatures[i] != nil {
					copy(uniqueSigs[i][:], signatures[i].Marshal())
				}
			}
		} else {
			// Slow path: split entries into numBatches batches.
			type batchEntry struct {
				uniqueIdx int
				account   e2wtypes.Account
				data      []byte
			}
			batchSizes := make([]int, numBatches)
			for _, count := range accountOccurrences {
				for b := range count {
					batchSizes[b]++
				}
			}
			batches := make([][]batchEntry, numBatches)
			for i := range batches {
				batches[i] = make([]batchEntry, 0, batchSizes[i])
			}
			batchAssignment := make(map[uuid.UUID]int, len(uniqueAccounts))
			for i, acct := range uniqueAccounts {
				id := acct.ID()
				batchIdx := batchAssignment[id]
				batchAssignment[id] = batchIdx + 1
				batches[batchIdx] = append(batches[batchIdx], batchEntry{
					uniqueIdx: i,
					account:   acct,
					data:      uniqueData[i],
				})
			}

			for _, batch := range batches {
				batchAccounts := make([]e2wtypes.Account, len(batch))
				batchData := make([][]byte, len(batch))
				for j, entry := range batch {
					batchAccounts[j] = entry.account
					batchData[j] = entry.data
				}
				signatures, err := multiSigner.SignGenericMulti(ctx, batchAccounts, batchData, domain[:])
				if err != nil {
					return []phase0.BLSSignature{}, err
				}
				for j, entry := range batch {
					if signatures[j] != nil {
						copy(uniqueSigs[entry.uniqueIdx][:], signatures[j].Marshal())
					}
				}
			}
		}
	} else {
		for i := range uniqueAccounts {
			container := phase0.SigningData{
				ObjectRoot: uniqueRoots[i],
				Domain:     domain,
			}
			hashTreeRoot, err := container.HashTreeRoot()
			if err != nil {
				return []phase0.BLSSignature{}, errors.Wrap(err, "failed to generate hash tree root")
			}
			signer, isAccountSigner := uniqueAccounts[i].(e2wtypes.AccountSigner)
			if !isAccountSigner {
				return []phase0.BLSSignature{}, errors.New("unknown signer type; cannot sign")
			}
			sig, err := signer.Sign(ctx, hashTreeRoot[:])
			if err != nil {
				return []phase0.BLSSignature{}, err
			}
			copy(uniqueSigs[i][:], sig.Marshal())
		}
	}

	// Map unique signatures back to all original positions.
	sigs := make([]phase0.BLSSignature, len(accounts))
	for i := range accounts {
		sigs[i] = uniqueSigs[indexMapping[i]]
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
