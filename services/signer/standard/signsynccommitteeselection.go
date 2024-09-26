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

// SignSyncCommitteeSelection returns a sync committee selection signature.
// This signs a slot and subcommittee with the "sync committee selection proof" domain.
func (s *Service) SignSyncCommitteeSelection(ctx context.Context,
	account e2wtypes.Account,
	slot phase0.Slot,
	subcommitteeIndex uint64,
) (
	phase0.BLSSignature,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.signer.standard").Start(ctx, "SignSyncCommitteeSelection")
	defer span.End()

	if s.syncCommitteeSelectionProofDomainType == nil {
		return phase0.BLSSignature{}, errors.New("no sync committee selection proof domain type, cannot sign")
	}

	// Calculate the domain.
	domain, err := s.domainProvider.Domain(ctx,
		*s.syncCommitteeSelectionProofDomainType,
		phase0.Epoch(slot/s.slotsPerEpoch))
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for sync committee selection proof")
	}

	selectionData := &altair.SyncAggregatorSelectionData{
		Slot:              slot,
		SubcommitteeIndex: subcommitteeIndex,
	}
	root, err := selectionData.HashTreeRoot()
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain hash tree root of sync aggregator selection data")
	}

	sig, err := s.sign(ctx, account, root, domain)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to sign sync committee selection proof")
	}

	return sig, nil
}

// SignSyncCommitteeSelections returns multiple sync committee selection signatures.
// This signs a slot and subcommittee with the "sync committee selection proof" domain.
func (s *Service) SignSyncCommitteeSelections(ctx context.Context,
	accounts []e2wtypes.Account,
	slot phase0.Slot,
	subcommitteeIndices []uint64,
) (
	[]phase0.BLSSignature,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.signer.standard").Start(ctx, "SignSyncCommitteeSelections")
	defer span.End()

	if s.syncCommitteeSelectionProofDomainType == nil {
		return []phase0.BLSSignature{}, errors.New("no sync committee selection proof domain type, cannot sign")
	}

	// Calculate the domain.
	domain, err := s.domainProvider.Domain(ctx,
		*s.syncCommitteeSelectionProofDomainType,
		phase0.Epoch(slot/s.slotsPerEpoch))
	if err != nil {
		return []phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for sync committee selection proof")
	}

	// Need to break the single request in to two: those for accounts and those for distributed accounts.
	// This is because they operate differently (single shot Vs. threshold signing).
	// We also keep a map to allow us to reassemble the signatures in the correct order.
	signingAccountRoots := make([]phase0.Root, 0, len(subcommitteeIndices))
	accountSigMap := make(map[int]int)
	signingAccounts := make([]e2wtypes.Account, 0, len(accounts))
	distributedAccountRoots := make([]phase0.Root, 0, len(subcommitteeIndices))
	distributedAccountSigMap := make(map[int]int)
	signingDistributedAccounts := make([]e2wtypes.Account, 0, len(accounts))
	for i := range accounts {
		if _, isDistributedAccount := accounts[i].(e2wtypes.DistributedAccount); isDistributedAccount {
			signingDistributedAccounts = append(signingDistributedAccounts, accounts[i])
			distributedAccountSigMap[len(signingDistributedAccounts)-1] = i
			root, err := getSyncCommitteeSelectionRoot(slot, subcommitteeIndices[i])
			if err != nil {
				return nil, err
			}
			distributedAccountRoots = append(distributedAccountRoots, root)
		} else {
			signingAccounts = append(signingAccounts, accounts[i])
			accountSigMap[len(signingAccounts)-1] = i
			root, err := getSyncCommitteeSelectionRoot(slot, subcommitteeIndices[i])
			if err != nil {
				return nil, err
			}
			signingAccountRoots = append(signingAccountRoots, root)
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

func getSyncCommitteeSelectionRoot(slot phase0.Slot, subcommitteeIndex uint64) (phase0.Root, error) {
	selectionData := &altair.SyncAggregatorSelectionData{
		Slot:              slot,
		SubcommitteeIndex: subcommitteeIndex,
	}
	root, err := selectionData.HashTreeRoot()
	if err != nil {
		return phase0.Root{}, errors.Wrap(err, "failed to obtain hash tree root of sync aggregator selection data")
	}
	return root, nil
}
