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

package wallet

import (
	"context"
	"encoding/binary"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// ValidatingAccount is a wrapper around the wallet account that implements ValidatingAccount.
type ValidatingAccount struct {
	account                 e2wtypes.Account
	index                   uint64
	state                   api.ValidatorState
	accountManager          *Service
	signatureDomainProvider eth2client.SignatureDomainProvider
}

// PubKey returns the public key of the validating account.
func (d *ValidatingAccount) PubKey(ctx context.Context) ([]byte, error) {
	if provider, isProvider := d.account.(e2wtypes.AccountCompositePublicKeyProvider); isProvider {
		return provider.CompositePublicKey().Marshal(), nil
	}
	return d.account.PublicKey().Marshal(), nil
}

// Index returns the index of the validating account.
func (d *ValidatingAccount) Index(ctx context.Context) (uint64, error) {
	return d.index, nil
}

// State returns the state of the validating account.
func (d *ValidatingAccount) State() api.ValidatorState {
	return d.state
}

// SignSlotSelection returns a slot selection signature.
// This signs a slot with the "selection proof" domain.
func (d *ValidatingAccount) SignSlotSelection(ctx context.Context, slot uint64) ([]byte, error) {
	messageRoot := make([]byte, 32)
	binary.LittleEndian.PutUint64(messageRoot, slot)

	// Calculate the signature domain.
	domain, err := d.signatureDomainProvider.SignatureDomain(ctx,
		d.accountManager.selectionProofDomain,
		slot/d.accountManager.slotsPerEpoch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for selection proof")
	}

	return d.sign(ctx, messageRoot, domain)
}

// SignRANDAOReveal returns a RANDAO reveal signature.
// This signs an epoch with the "RANDAO reveal" domain.
// N.B. This passes in a slot, not an epoch.
func (d *ValidatingAccount) SignRANDAOReveal(ctx context.Context, slot uint64) ([]byte, error) {
	messageRoot := make([]byte, 32)
	epoch := slot / d.accountManager.slotsPerEpoch
	binary.LittleEndian.PutUint64(messageRoot, epoch)

	// Obtain the RANDAO reveal signature domain.
	domain, err := d.signatureDomainProvider.SignatureDomain(ctx,
		d.accountManager.randaoDomain,
		epoch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for RANDAO reveal")
	}

	return d.sign(ctx, messageRoot, domain)
}

// SignBeaconBlockProposal signs a beacon block proposal item.
func (d *ValidatingAccount) SignBeaconBlockProposal(ctx context.Context,
	slot uint64,
	proposerIndex uint64,
	parentRoot []byte,
	stateRoot []byte,
	bodyRoot []byte) ([]byte, error) {

	message := &spec.BeaconBlockHeader{
		Slot:          slot,
		ProposerIndex: proposerIndex,
		ParentRoot:    parentRoot,
		StateRoot:     stateRoot,
		BodyRoot:      bodyRoot,
	}
	messageRoot, err := message.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain hash tree root of block")
	}

	// Obtain the signature domain.
	domain, err := d.signatureDomainProvider.SignatureDomain(ctx,
		d.accountManager.beaconProposerDomain,
		slot/d.accountManager.slotsPerEpoch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for beacon proposal")
	}

	return d.sign(ctx, messageRoot[:], domain)
}

// SignBeaconAttestation signs a beacon attestation item.
func (d *ValidatingAccount) SignBeaconAttestation(ctx context.Context,
	slot uint64,
	committeeIndex uint64,
	blockRoot []byte,
	sourceEpoch uint64,
	sourceRoot []byte,
	targetEpoch uint64,
	targetRoot []byte) ([]byte, error) {

	message := &spec.AttestationData{
		Slot:            slot,
		Index:           committeeIndex,
		BeaconBlockRoot: blockRoot,
		Source: &spec.Checkpoint{
			Epoch: sourceEpoch,
			Root:  sourceRoot,
		},
		Target: &spec.Checkpoint{
			Epoch: targetEpoch,
			Root:  targetRoot,
		},
	}
	messageRoot, err := message.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain hash tree root of attestation data")
	}

	domain, err := d.signatureDomainProvider.SignatureDomain(ctx,
		d.accountManager.beaconAttesterDomain,
		slot/d.accountManager.slotsPerEpoch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for beacon attestation")
	}

	return d.sign(ctx, messageRoot[:], domain)
}

// SignAggregateAndProof signs an aggregate and proof item.
func (d *ValidatingAccount) SignAggregateAndProof(ctx context.Context, slot uint64, aggregateAndProofRoot []byte) ([]byte, error) {

	// Fetch the signature domain.
	domain, err := d.signatureDomainProvider.SignatureDomain(ctx,
		d.accountManager.aggregateAndProofDomain,
		slot)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for beacon aggregate and proof")
	}

	return d.sign(ctx, aggregateAndProofRoot, domain)
}

func (d *ValidatingAccount) sign(ctx context.Context, messageRoot []byte, domain []byte) ([]byte, error) {
	container := &SigningContainer{
		Root:   messageRoot,
		Domain: domain,
	}
	signingRoot, err := container.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate hash tree root for signing container")
	}

	sig, err := d.account.(e2wtypes.AccountSigner).Sign(ctx, signingRoot[:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign beacon block proposal")
	}
	return sig.Marshal(), nil
}
