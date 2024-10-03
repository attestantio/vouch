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

// Package signer is a package that provides application-level signing operations.
package signer

import (
	"context"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is the generic signer service.
type Service interface{}

// AggregateAndProofSigner provides methods to sign aggregate and proofs.
type AggregateAndProofSigner interface {
	// SignAggregateAndProof signs an aggregate attestation for given slot and root.
	SignAggregateAndProof(ctx context.Context,
		account e2wtypes.Account,
		slot phase0.Slot,
		root phase0.Root,
	) (
		phase0.BLSSignature,
		error,
	)
}

// BeaconAttestationSigner provides methods to sign beacon attestations.
type BeaconAttestationSigner interface {
	// SignBeaconAttestation signs a beacon attestation.
	SignBeaconAttestation(ctx context.Context,
		account e2wtypes.Account,
		slot phase0.Slot,
		committeeIndex phase0.CommitteeIndex,
		blockRoot phase0.Root,
		sourceEpoch phase0.Epoch,
		sourceRoot phase0.Root,
		targetEpoch phase0.Epoch,
		targetRoot phase0.Root,
	) (
		phase0.BLSSignature,
		error,
	)
}

// BeaconAttestationsSigner provides methods to sign multiple beacon attestations.
type BeaconAttestationsSigner interface {
	// SignBeaconAttestations signs multiple beacon attestations.
	SignBeaconAttestations(ctx context.Context,
		accounts []e2wtypes.Account,
		slot phase0.Slot,
		committeeIndices []phase0.CommitteeIndex,
		blockRoot phase0.Root,
		sourceEpoch phase0.Epoch,
		sourceRoot phase0.Root,
		targetEpoch phase0.Epoch,
		targetRoot phase0.Root,
	) (
		[]phase0.BLSSignature,
		error,
	)
}

// BeaconBlockSigner provides methods to sign beacon blocks.
type BeaconBlockSigner interface {
	// SignBeaconBlockProposal signs a beacon block proposal.
	SignBeaconBlockProposal(ctx context.Context,
		account e2wtypes.Account,
		slot phase0.Slot,
		proposerIndex phase0.ValidatorIndex,
		parentRoot phase0.Root,
		stateRoot phase0.Root,
		bodyRoot phase0.Root,
	) (
		phase0.BLSSignature,
		error,
	)
}

// BlobSidecarSigner provides methods to sign blob sidecars.
type BlobSidecarSigner interface {
	// SignBlobSidecar signs a blob sidecar proposal.
	SignBlobSidecar(ctx context.Context,
		account e2wtypes.Account,
		slot phase0.Slot,
		blobSidecarRoot phase0.Root,
	) (
		phase0.BLSSignature,
		error,
	)
}

// RANDAORevealSigner provides methods to sign RANDAO reveals.
type RANDAORevealSigner interface {
	// SignRANDAOReveal returns a RANDAO signature.
	// This signs an epoch with the "RANDAO" domain.
	SignRANDAOReveal(ctx context.Context,
		account e2wtypes.Account,
		slot phase0.Slot,
	) (
		phase0.BLSSignature,
		error,
	)
}

// SlotSelectionSigner provides methods to sign slot selections.
type SlotSelectionSigner interface {
	// SignSlotSelections returns multiple slot selection signatures.
	// This signs a slot with the "selection proof" domain.
	SignSlotSelections(ctx context.Context,
		accounts []e2wtypes.Account,
		slot phase0.Slot,
	) (
		[]phase0.BLSSignature,
		error,
	)
}

// SyncCommitteeRootSigner provides methods to sign a sync committee root.
type SyncCommitteeRootSigner interface {
	// SignSyncCommitteeRoots returns root signatures.
	// This signs a beacon block root with the "sync committee" domain.
	SignSyncCommitteeRoots(ctx context.Context,
		accounts []e2wtypes.Account,
		epoch phase0.Epoch,
		root phase0.Root,
	) (
		[]phase0.BLSSignature,
		error,
	)
}

// SyncCommitteeSelectionSigner provides methods to sign sync committee selections.
type SyncCommitteeSelectionSigner interface {
	// SignSyncCommitteeSelections returns multiple sync committee selection signatures.
	// This signs a slot and subcommittee with the "sync committee selection proof" domain.
	SignSyncCommitteeSelections(ctx context.Context,
		accounts []e2wtypes.Account,
		slot phase0.Slot,
		subcommitteeIndices []uint64,
	) (
		[]phase0.BLSSignature,
		error,
	)
}

// ContributionAndProofSigner provides methods to sign contribution and proofs.
type ContributionAndProofSigner interface {
	// SignContributionAndProofs signs multiple sync committee contributions for multiple accounts.
	SignContributionAndProofs(ctx context.Context,
		accounts []e2wtypes.Account,
		contributionAndProofs []*altair.ContributionAndProof,
	) (
		[]phase0.BLSSignature,
		error,
	)
}

// ValidatorRegistrationSigner provides methods to sign validator registrations.
type ValidatorRegistrationSigner interface {
	// SignValidatorRegistration signs a validator registration.
	SignValidatorRegistration(ctx context.Context,
		account e2wtypes.Account,
		registration *api.VersionedValidatorRegistration,
	) (
		phase0.BLSSignature,
		error,
	)
}
