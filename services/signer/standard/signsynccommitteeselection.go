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
