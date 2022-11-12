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

// Package accountmanager is a package that manages validator accounts from multiple sources.
package accountmanager

import (
	"context"

	api "github.com/attestantio/go-eth2-client/api/v1"
)

// Service is the generic accountmanager service.
type Service interface{}

// ValidatingAccountsProvider provides methods for validating accounts.
type ValidatingAccountsProvider interface {
	// Accounts provides information about all accounts that are configured to validate through this instance.
	Accounts(ctx context.Context) ([]ValidatingAccount, error)

	// AccountsByIndex provides information about the specific accounts that are configured to validate through this instance.
	AccountsByIndex(ctx context.Context, indices []uint64) ([]ValidatingAccount, error)

	// AccountsByPubKey provides information about the specific accounts that are configured to validate through this instance.
	AccountsByPubKey(ctx context.Context, pubKeys [][]byte) ([]ValidatingAccount, error)
}

// ValidatingAccountPubKeyProvider provides methods for obtaining public keys from accounts.
type ValidatingAccountPubKeyProvider interface {
	// PubKey() provides the public key for this account.
	PubKey(ctx context.Context) ([]byte, error)
}

// ValidatingAccountIndexProvider provides methods for obtaining indices from accounts.
type ValidatingAccountIndexProvider interface {
	// Index() provides the validator index for this account.
	// Returns an error if there is no index for this validator.
	Index(ctx context.Context) (uint64, error)
}

// ValidatingAccountStateProvider provides methods for obtaining state from accounts.
type ValidatingAccountStateProvider interface {
	// State() provides the validator state for this account.
	State() api.ValidatorState
}

// ValidatingAccount is a composite interface for common validating account features.
type ValidatingAccount interface {
	ValidatingAccountPubKeyProvider
	ValidatingAccountIndexProvider
	ValidatingAccountStateProvider
}

// AccountsFetcher fetches accounts from the remote source.
type AccountsFetcher interface {
	// RefreshAccounts refreshes the list of relevant accounts known by the account manager.
	RefreshAccounts(ctx context.Context) error
}

// AccountsUpdater manages updates to accounts in line with internal and external changes.
type AccountsUpdater interface {
	// UpdateAccountsState updates account state with the latest information from the beacon chain.
	UpdateAccountsState(ctx context.Context) error
}

// IsAggregatorProvider provides methods for obtaining aggregation status from accounts.
type IsAggregatorProvider interface {
}

// RANDAORevealSigner provides methods to sign RANDAO reveals.
type RANDAORevealSigner interface {
	// SignRANDAOReveal returns a RANDAO signature.
	// This signs an epoch with the "RANDAO" domain.
	// N.B. This passes in a slot, not an epoch.
	SignRANDAOReveal(ctx context.Context, slot uint64) ([]byte, error)
}

// SlotSelectionSigner provides methods to sign slot selections.
type SlotSelectionSigner interface {
	// SignSlotSelection returns a slot selection signature.
	// This signs a slot with the "selection proof" domain.
	SignSlotSelection(ctx context.Context, slot uint64) ([]byte, error)
}

// BeaconBlockSigner provides methods to sign beacon blocks.
type BeaconBlockSigner interface {
	// SignBeaconBlockProposal signs a beacon block proposal.
	SignBeaconBlockProposal(ctx context.Context,
		slot uint64,
		proposerIndex uint64,
		parentRoot []byte,
		stateRoot []byte,
		bodyRoot []byte) ([]byte, error)
}

// BeaconAttestationSigner provides methods to sign beacon attestations.
type BeaconAttestationSigner interface {
	// SignBeaconAttestation signs a beacon attestation.
	SignBeaconAttestation(ctx context.Context,
		slot uint64,
		committeeIndex uint64,
		blockRoot []byte,
		sourceEpoch uint64,
		sourceRoot []byte,
		targetEpoch uint64,
		targetRoot []byte) ([]byte, error)
}

// BeaconAttestationsSigner provides methods to sign multiple beacon attestations.
type BeaconAttestationsSigner interface {
	// SignBeaconAttestation signs multiple beacon attestations.
	SignBeaconAttestations(ctx context.Context,
		slot uint64,
		accounts []ValidatingAccount,
		committeeIndices []uint64,
		blockRoot []byte,
		sourceEpoch uint64,
		sourceRoot []byte,
		targetEpoch uint64,
		targetRoot []byte) ([][]byte, error)
}

// AggregateAndProofSigner provides methods to sign aggregate and proofs.
type AggregateAndProofSigner interface {
	// SignAggregateAndProof signs an aggregate attestation for given slot and root.
	SignAggregateAndProof(ctx context.Context, slot uint64, root []byte) ([]byte, error)
}

// Signer is a composite interface for all signer operations.
type Signer interface {
	RANDAORevealSigner
	SlotSelectionSigner
	BeaconBlockSigner
	BeaconAttestationSigner
	AggregateAndProofSigner
}
