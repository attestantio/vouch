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

// Package signer is a package that provides application-level signing operations.
package signer

import (
	"context"

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is the generic signer service.
type Service interface{}

// AggregateAndProofSigner provides methods to sign aggregate and proofs.
type AggregateAndProofSigner interface {
	// SignAggregateAndProof signs an aggregate attestation for given slot and root.
	SignAggregateAndProof(ctx context.Context,
		account e2wtypes.Account,
		slot spec.Slot,
		root spec.Root,
	) (
		spec.BLSSignature,
		error,
	)
}

// BeaconAttestationSigner provides methods to sign beacon attestations.
type BeaconAttestationSigner interface {
	// SignBeaconAttestation signs a beacon attestation.
	SignBeaconAttestation(ctx context.Context,
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
	)
}

// BeaconAttestationsSigner provides methods to sign multiple beacon attestations.
type BeaconAttestationsSigner interface {
	// SignBeaconAttestation signs multiple beacon attestations.
	SignBeaconAttestations(ctx context.Context,
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
	)
}

// BeaconBlockSigner provides methods to sign beacon blocks.
type BeaconBlockSigner interface {
	// SignBeaconBlockProposal signs a beacon block proposal.
	SignBeaconBlockProposal(ctx context.Context,
		account e2wtypes.Account,
		slot spec.Slot,
		proposerIndex spec.ValidatorIndex,
		parentRoot spec.Root,
		stateRoot spec.Root,
		bodyRoot spec.Root,
	) (
		spec.BLSSignature,
		error,
	)
}

// RANDAORevealSigner provides methods to sign RANDAO reveals.
type RANDAORevealSigner interface {
	// SignRANDAOReveal returns a RANDAO signature.
	// This signs an epoch with the "RANDAO" domain.
	SignRANDAOReveal(ctx context.Context,
		account e2wtypes.Account,
		slot spec.Slot,
	) (
		spec.BLSSignature,
		error,
	)
}

// SlotSelectionSigner provides methods to sign slot selections.
type SlotSelectionSigner interface {
	// SignSlotSelection returns a slot selection signature.
	// This signs a slot with the "selection proof" domain.
	SignSlotSelection(ctx context.Context,
		account e2wtypes.Account,
		slot spec.Slot,
	) (
		spec.BLSSignature,
		error,
	)
}
