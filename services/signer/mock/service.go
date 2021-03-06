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

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// service is a mock.
type Service struct{}

// New provides a mock signer.
func New() *Service {
	return &Service{}
}

// SignAggregateAndProof signs an aggregate attestation for given slot and root.
func (s *Service) SignAggregateAndProof(ctx context.Context,
	account e2wtypes.Account,
	slot spec.Slot,
	root spec.Root,
) (
	spec.BLSSignature,
	error,
) {
	return spec.BLSSignature{}, nil
}

// SignBeaconAttestation signs a beacon attestation.
func (s *Service) SignBeaconAttestation(ctx context.Context,
	account e2wtypes.Account,
	slot spec.Slot,
	committeeIndex spec.CommitteeIndex,
	blockRoot spec.Root,
	sourceEpoch spec.Epoch,
	sourceRoot spec.Root,
	targetEpoch spec.Epoch,
	targetRoot spec.Root,
) (
	spec.BLSSignature,
	error,
) {
	return spec.BLSSignature{}, nil
}

// SignBeaconAttestation signs multiple beacon attestations.
func (s *Service) SignBeaconAttestations(ctx context.Context,
	accounts []e2wtypes.Account,
	slot spec.Slot,
	committeeIndices []spec.CommitteeIndex,
	blockRoot spec.Root,
	sourceEpoch spec.Epoch,
	sourceRoot spec.Root,
	targetEpoch spec.Epoch,
	targetRoot spec.Root,
) (
	[]spec.BLSSignature,
	error,
) {
	return []spec.BLSSignature{}, nil
}

// SignBeaconBlockProposal signs a beacon block proposal.
func (s *Service) SignBeaconBlockProposal(ctx context.Context,
	account e2wtypes.Account,
	slot spec.Slot,
	proposerIndex spec.ValidatorIndex,
	parentRoot spec.Root,
	stateRoot spec.Root,
	bodyRoot spec.Root,
) (
	spec.BLSSignature,
	error,
) {
	return spec.BLSSignature{}, nil
}

// SignRANDAOReveal returns a RANDAO signature.
// This signs an epoch with the "RANDAO" domain.
func (s *Service) SignRANDAOReveal(ctx context.Context,
	account e2wtypes.Account,
	slot spec.Slot,
) (
	spec.BLSSignature,
	error,
) {
	return spec.BLSSignature{}, nil
}

// SignSlotSelection returns a slot selection signature.
// This signs a slot with the "selection proof" domain.
func (s *Service) SignSlotSelection(ctx context.Context,
	account e2wtypes.Account,
	slot spec.Slot,
) (
	spec.BLSSignature,
	error,
) {
	return spec.BLSSignature{}, nil
}
