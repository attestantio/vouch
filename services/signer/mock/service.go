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

package mock

import (
	"context"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is a mock.
type Service struct{}

// New provides a mock signer.
func New() *Service {
	return &Service{}
}

// SignAggregateAndProof signs an aggregate attestation for given slot and root.
func (*Service) SignAggregateAndProof(_ context.Context,
	_ e2wtypes.Account,
	_ phase0.Slot,
	_ phase0.Root,
) (
	phase0.BLSSignature,
	error,
) {
	return phase0.BLSSignature{}, nil
}

// SignBeaconAttestation signs a beacon attestation.
func (*Service) SignBeaconAttestation(_ context.Context,
	_ e2wtypes.Account,
	_ phase0.Slot,
	_ phase0.CommitteeIndex,
	_ phase0.Root,
	_ phase0.Epoch,
	_ phase0.Root,
	_ phase0.Epoch,
	_ phase0.Root,
) (
	phase0.BLSSignature,
	error,
) {
	return phase0.BLSSignature{}, nil
}

// SignBeaconAttestations signs multiple beacon attestations.
func (*Service) SignBeaconAttestations(_ context.Context,
	_ []e2wtypes.Account,
	_ phase0.Slot,
	_ []phase0.CommitteeIndex,
	_ phase0.Root,
	_ phase0.Epoch,
	_ phase0.Root,
	_ phase0.Epoch,
	_ phase0.Root,
) (
	[]phase0.BLSSignature,
	error,
) {
	return []phase0.BLSSignature{}, nil
}

// SignBeaconBlockProposal signs a beacon block proposal.
func (*Service) SignBeaconBlockProposal(_ context.Context,
	_ e2wtypes.Account,
	_ phase0.Slot,
	_ phase0.ValidatorIndex,
	_ phase0.Root,
	_ phase0.Root,
	_ phase0.Root,
) (
	phase0.BLSSignature,
	error,
) {
	return phase0.BLSSignature{}, nil
}

// SignRANDAOReveal returns a RANDAO signature.
// This signs an epoch with the "RANDAO" domain.
func (*Service) SignRANDAOReveal(_ context.Context,
	_ e2wtypes.Account,
	_ phase0.Slot,
) (
	phase0.BLSSignature,
	error,
) {
	return phase0.BLSSignature{}, nil
}

// SignSlotSelection returns a slot selection signature.
// This signs a slot with the "selection proof" domain.
func (*Service) SignSlotSelection(_ context.Context,
	_ e2wtypes.Account,
	_ phase0.Slot,
) (
	phase0.BLSSignature,
	error,
) {
	return phase0.BLSSignature{}, nil
}

// SignContributionAndProof signs a sync committee contribution for given slot and root.
func (*Service) SignContributionAndProof(_ context.Context,
	_ e2wtypes.Account,
	_ *altair.ContributionAndProof,
) (
	phase0.BLSSignature,
	error,
) {
	return phase0.BLSSignature{}, nil
}

// SignSyncCommitteeRoot returns a root signature.
// This signs a beacon block root with the "sync committee" domain.
func (*Service) SignSyncCommitteeRoot(_ context.Context,
	_ e2wtypes.Account,
	_ phase0.Epoch,
	_ phase0.Root,
) (
	phase0.BLSSignature,
	error,
) {
	return phase0.BLSSignature{}, nil
}

// SignSyncCommitteeSelection returns a sync committee selection signature.
// This signs a slot and subcommittee with the "sync committee selection proof" domain.
func (*Service) SignSyncCommitteeSelection(_ context.Context,
	_ e2wtypes.Account,
	_ phase0.Slot,
	_ uint64,
) (
	phase0.BLSSignature,
	error,
) {
	return phase0.BLSSignature{}, nil
}

// SignValidatorRegistration signs a validator registration.
func (*Service) SignValidatorRegistration(_ context.Context,
	_ e2wtypes.Account,
	_ *api.VersionedValidatorRegistration,
) (
	phase0.BLSSignature,
	error,
) {
	return phase0.BLSSignature{}, nil
}
