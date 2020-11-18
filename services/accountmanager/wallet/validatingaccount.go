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
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/pkg/errors"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// ValidatingAccount is a wrapper around the wallet account that implements ValidatingAccount.
type ValidatingAccount struct {
	account        e2wtypes.Account
	index          spec.ValidatorIndex
	state          api.ValidatorState
	accountManager *Service
	domainProvider eth2client.DomainProvider
}

// PubKey returns the public key of the validating account.
func (d *ValidatingAccount) PubKey(ctx context.Context) (spec.BLSPubKey, error) {
	var pubKey spec.BLSPubKey
	if provider, isProvider := d.account.(e2wtypes.AccountCompositePublicKeyProvider); isProvider {
		copy(pubKey[:], provider.CompositePublicKey().Marshal())
	} else {
		copy(pubKey[:], d.account.PublicKey().Marshal())
	}
	return pubKey, nil
}

// Index returns the index of the validating account.
func (d *ValidatingAccount) Index(ctx context.Context) (spec.ValidatorIndex, error) {
	return d.index, nil
}

// State returns the state of the validating account.
func (d *ValidatingAccount) State() api.ValidatorState {
	return d.state
}

// SignSlotSelection returns a slot selection signature.
// This signs a slot with the "selection proof" domain.
func (d *ValidatingAccount) SignSlotSelection(ctx context.Context, slot spec.Slot) (spec.BLSSignature, error) {
	var messageRoot spec.Root
	binary.LittleEndian.PutUint64(messageRoot[:], uint64(slot))

	// Calculate the domain.
	domain, err := d.domainProvider.Domain(ctx,
		d.accountManager.selectionProofDomain,
		spec.Epoch(slot/d.accountManager.slotsPerEpoch))
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain domain for selection proof")
	}

	return d.sign(ctx, messageRoot, domain)
}

// SignRANDAOReveal returns a RANDAO reveal signature.
// This signs an epoch with the "RANDAO reveal" domain.
func (d *ValidatingAccount) SignRANDAOReveal(ctx context.Context, slot spec.Slot) (spec.BLSSignature, error) {
	var messageRoot spec.Root
	epoch := spec.Epoch(slot / d.accountManager.slotsPerEpoch)
	binary.LittleEndian.PutUint64(messageRoot[:], uint64(epoch))

	// Obtain the RANDAO reveal signature domain.
	domain, err := d.domainProvider.Domain(ctx,
		d.accountManager.randaoDomain,
		epoch)
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for RANDAO reveal")
	}

	var epochBytes spec.Root
	binary.LittleEndian.PutUint64(epochBytes[:], uint64(epoch))

	return d.sign(ctx, epochBytes, domain)
}

// SignBeaconBlockProposal signs a beacon block proposal item.
func (d *ValidatingAccount) SignBeaconBlockProposal(ctx context.Context,
	slot spec.Slot,
	proposerIndex spec.ValidatorIndex,
	parentRoot spec.Root,
	stateRoot spec.Root,
	bodyRoot spec.Root) (spec.BLSSignature, error) {

	message := &spec.BeaconBlockHeader{
		Slot:          slot,
		ProposerIndex: proposerIndex,
		ParentRoot:    parentRoot,
		StateRoot:     stateRoot,
		BodyRoot:      bodyRoot,
	}
	messageRoot, err := message.HashTreeRoot()
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain hash tree root of block")
	}

	// Fetch the domain.
	domain, err := d.domainProvider.Domain(ctx,
		d.accountManager.beaconProposerDomain,
		spec.Epoch(slot/d.accountManager.slotsPerEpoch))
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for beacon proposal")
	}

	return d.sign(ctx, messageRoot, domain)
}

// SignBeaconAttestations signs multiple beacon attestations.
func (d *ValidatingAccount) SignBeaconAttestations(ctx context.Context,
	slot spec.Slot,
	accounts []accountmanager.ValidatingAccount,
	committeeIndices []spec.CommitteeIndex,
	blockRoot spec.Root,
	sourceEpoch spec.Epoch,
	sourceRoot spec.Root,
	targetEpoch spec.Epoch,
	targetRoot spec.Root) ([]spec.BLSSignature, error) {

	signatures := make([]spec.BLSSignature, len(accounts))
	var err error
	for i, account := range accounts {
		signatures[i], err = account.(*ValidatingAccount).SignBeaconAttestation(ctx,
			slot,
			committeeIndices[i],
			blockRoot,
			sourceEpoch,
			sourceRoot,
			targetEpoch,
			targetRoot)
		if err != nil {
			return nil, err
		}
	}

	return signatures, nil
}

// SignBeaconAttestation signs a beacon attestation item.
func (d *ValidatingAccount) SignBeaconAttestation(ctx context.Context,
	slot spec.Slot,
	committeeIndex spec.CommitteeIndex,
	blockRoot spec.Root,
	sourceEpoch spec.Epoch,
	sourceRoot spec.Root,
	targetEpoch spec.Epoch,
	targetRoot spec.Root) (spec.BLSSignature, error) {

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
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain hash tree root of attestation data")
	}

	domain, err := d.domainProvider.Domain(ctx,
		d.accountManager.beaconAttesterDomain,
		spec.Epoch(slot/d.accountManager.slotsPerEpoch))
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for beacon attestation")
	}

	return d.sign(ctx, messageRoot, domain)
}

// SignAggregateAndProof signs an aggregate and proof item.
func (d *ValidatingAccount) SignAggregateAndProof(ctx context.Context, slot spec.Slot, aggregateAndProofRoot spec.Root) (spec.BLSSignature, error) {
	// Fetch the signature domain.
	domain, err := d.domainProvider.Domain(ctx,
		d.accountManager.aggregateAndProofDomain,
		spec.Epoch(slot/d.accountManager.slotsPerEpoch))
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for beacon aggregate and proof")
	}

	return d.sign(ctx, aggregateAndProofRoot, domain)
}

func (d *ValidatingAccount) sign(ctx context.Context, message spec.Root, domain spec.Domain) (spec.BLSSignature, error) {
	var sig e2types.Signature
	var err error
	if protectingSigner, isProtectingSigner := d.account.(e2wtypes.AccountProtectingSigner); isProtectingSigner {
		sig, err = protectingSigner.SignGeneric(ctx, message[:], domain[:])
	} else {
		// Create the root manually.
		container := &spec.SigningData{
			ObjectRoot: message,
			Domain:     domain,
		}
		var signingRoot spec.Root
		signingRoot, err = container.HashTreeRoot()
		if err != nil {
			return spec.BLSSignature{}, errors.Wrap(err, "failed to generate hash tree root for signing container")
		}

		sig, err = d.account.(e2wtypes.AccountSigner).Sign(ctx, signingRoot[:])
	}
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to sign")
	}

	var signature spec.BLSSignature
	copy(signature[:], sig.Marshal())
	return signature, nil
}
