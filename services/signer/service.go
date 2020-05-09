package signer

import "context"

type RandaoRevealSigner interface {
	// SignRanDAOReveal returns a RANDAO signature.
	// This signs an epoch with the "RANDAO" domain.
	SignRandaoReveal(ctx context.Context, pubKey []byte, epoch uint64) ([]byte, error)
}

type SlotSelectionSigner interface {
	// SignSlotSelection returns a slot selection signature.
	// This signs a slot with the "selection proof" domain.
	SignSlotSelection(ctx context.Context, pubKey []byte, epoch uint64) ([]byte, error)
}

type BeaconBlockSigner interface {
	// SignBeaconBlockProposal signs a beacon block proposal.
	// TODO beaconBlockheader needs to be a struct.
	SignBeaconBlockProposal(ctx context.Context, pubKey []byte, domain []byte, beaconBlockHeader []byte) ([]byte, error)
}

type BeaconAttestationSigner interface {
	// SignBeaconAttestation signs a beacon attestation.
	// TODO attestation needs to be a struct.
	SignBeaconAttestation(ctx context.Context, pubKey []byte, attestation []byte) ([]byte, error)
}

type BeaconAggregateAndProofSigner interface {
	// SignAggregateAndProof signs an aggregate attestation.
	// TODO aggregateAndProof needs to be a struct.
	SignAggregateAndProof(ctx context.Context, pubKey []byte, aggregateAndProof []byte) ([]byte, error)
}

// Signer is a composite interface for all signer operations.
type Signer interface {
	RandaoRevealSigner
	SlotSelectionSigner
	BeaconBlockSigner
	BeaconAttestationSigner
	BeaconAggregateAndProofSigner
}
