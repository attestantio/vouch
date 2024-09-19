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
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
)

// SignSyncCommitteeRoot returns a root signature.
// This signs a beacon block root with the "sync committee" domain.
func (s *Service) SignSyncCommitteeRoot(ctx context.Context,
	account e2wtypes.Account,
	epoch phase0.Epoch,
	root phase0.Root,
) (
	phase0.BLSSignature,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.signer.standard").Start(ctx, "SignSyncCommitteeRoot")
	defer span.End()

	if s.syncCommitteeDomainType == nil {
		return phase0.BLSSignature{}, errors.New("no sync committee domain type available; cannot sign")
	}

	// Calculate the domain.
	domain, err := s.domainProvider.Domain(ctx, *s.syncCommitteeDomainType, epoch)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for sync committee")
	}

	sig, err := s.sign(ctx, account, root, domain)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to sign sync committee root")
	}

	return sig, nil
}

// SignSyncCommitteeRoots returns root signatures.
// This signs a beacon block root with the "sync committee" domain.
func (s *Service) SignSyncCommitteeRoots(ctx context.Context,
	accounts []e2wtypes.Account,
	epoch phase0.Epoch,
	root phase0.Root,
) (
	[]phase0.BLSSignature,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.signer.standard").Start(ctx, "SignSyncCommitteeRoots")
	defer span.End()

	if s.syncCommitteeDomainType == nil {
		return []phase0.BLSSignature{}, errors.New("no sync committee domain type available; cannot sign")
	}

	// Calculate the domain.
	domain, err := s.domainProvider.Domain(ctx, *s.syncCommitteeDomainType, epoch)
	if err != nil {
		return []phase0.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for sync committee")
	}

	// Need to break the single request in to two: those for accounts and those for distributed accounts.
	// This is because they operate differently (single shot Vs. threshold signing).
	// We also keep a map to allow us to reassemble the signatures in the correct order.
	accountSigMap := make(map[int]int)
	signingAccounts := make([]e2wtypes.Account, 0, len(accounts))
	distributedAccountSigMap := make(map[int]int)
	signingDistributedAccounts := make([]e2wtypes.Account, 0, len(accounts))
	for i, account := range accounts {
		if account == nil {
			continue
		}
		if _, isDistributedAccount := account.(e2wtypes.DistributedAccount); isDistributedAccount {
			signingDistributedAccounts = append(signingDistributedAccounts, account)
			distributedAccountSigMap[len(signingDistributedAccounts)-1] = i
		} else {
			signingAccounts = append(signingAccounts, account)
			accountSigMap[len(signingAccounts)-1] = i
		}
	}

	// Because this function returns all or none of the signatures we run these in series. This ensures that we don't
	// end up in a situation where one Vouch instance obtains signatures for individual accounts and the other for distributed accounts,
	// which would result in neither of them returning the full set of signatures and hence both erroring out.
	sigs := make([]phase0.BLSSignature, len(accounts))
	if len(signingAccounts) > 0 {
		signatures, err := s.signRootMulti(ctx, signingAccounts, root, domain)
		if err != nil {
			return nil, errors.Wrap(err, "failed to sign for individual accounts")
		}
		for i := range signatures {
			sigs[accountSigMap[i]] = signatures[i]
		}
	}
	if len(signingDistributedAccounts) > 0 {
		signatures, err := s.signRootMulti(ctx, signingDistributedAccounts, root, domain)
		if err != nil {
			return nil, errors.Wrap(err, "failed to sign for distributed accounts")
		}
		for i := range signatures {
			sigs[distributedAccountSigMap[i]] = signatures[i]
		}
	}

	return sigs, nil
}
