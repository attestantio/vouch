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

package dirk

import (
	"context"
	"encoding/binary"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// ValidatingAccount is a wrapper around the dirk account that implements ValidatingAccount.
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
		d.accountManager.selectionProofDomainType,
		spec.Epoch(slot/d.accountManager.slotsPerEpoch))
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for selection proof")
	}

	slotBytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(slotBytes, uint64(slot))

	sig, err := d.account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx, slotBytes, domain[:])
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to sign slot")
	}

	var signature spec.BLSSignature
	copy(signature[:], sig.Marshal())
	return signature, nil
}

// SignRANDAOReveal returns a RANDAO reveal signature.
// This signs an epoch with the "RANDAO reveal" domain.
func (d *ValidatingAccount) SignRANDAOReveal(ctx context.Context, slot spec.Slot) (spec.BLSSignature, error) {
	var messageRoot spec.Root
	epoch := spec.Epoch(slot / d.accountManager.slotsPerEpoch)
	binary.LittleEndian.PutUint64(messageRoot[:], uint64(epoch))

	// Obtain the RANDAO reveal signature domain.
	domain, err := d.domainProvider.Domain(ctx,
		d.accountManager.randaoDomainType,
		epoch)
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for RANDAO reveal")
	}

	epochBytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(epochBytes, uint64(epoch))

	sig, err := d.account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx, epochBytes, domain[:])
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to sign RANDO reveal")
	}

	var signature spec.BLSSignature
	copy(signature[:], sig.Marshal())
	return signature, nil
}

// SignBeaconBlockProposal signs a beacon block proposal item.
func (d *ValidatingAccount) SignBeaconBlockProposal(ctx context.Context,
	slot spec.Slot,
	proposerIndex spec.ValidatorIndex,
	parentRoot spec.Root,
	stateRoot spec.Root,
	bodyRoot spec.Root) (spec.BLSSignature, error) {

	// Fetch the domain.
	domain, err := d.domainProvider.Domain(ctx,
		d.accountManager.beaconProposerDomainType,
		spec.Epoch(slot/d.accountManager.slotsPerEpoch))
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for beacon proposal")
	}

	sig, err := d.account.(e2wtypes.AccountProtectingSigner).SignBeaconProposal(ctx,
		uint64(slot),
		uint64(proposerIndex),
		parentRoot[:],
		stateRoot[:],
		bodyRoot[:],
		domain[:])
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to sign beacon block proposal")
	}

	var signature spec.BLSSignature
	copy(signature[:], sig.Marshal())
	return signature, nil
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

	domain, err := d.domainProvider.Domain(ctx,
		d.accountManager.beaconAttesterDomainType,
		spec.Epoch(slot/d.accountManager.slotsPerEpoch))
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for beacon attestation")
	}

	sig, err := d.account.(e2wtypes.AccountProtectingSigner).SignBeaconAttestation(ctx,
		uint64(slot),
		uint64(committeeIndex),
		blockRoot[:],
		uint64(sourceEpoch),
		sourceRoot[:],
		uint64(targetEpoch),
		targetRoot[:],
		domain[:])
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to sign beacon attestation")
	}

	var signature spec.BLSSignature
	copy(signature[:], sig.Marshal())
	return signature, nil
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
	span, ctx := opentracing.StartSpanFromContext(ctx, "dirk.SignBeaconAttestations")
	defer span.Finish()

	signatureDomain, err := d.domainProvider.Domain(ctx,
		d.accountManager.beaconAttesterDomainType,
		spec.Epoch(slot/d.accountManager.slotsPerEpoch))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for beacon attestation")
	}

	e2Accounts := make([]e2wtypes.Account, len(accounts))
	for i := range accounts {
		e2Accounts[i] = accounts[i].(*ValidatingAccount).account
	}
	uintCommitteeIndices := make([]uint64, len(committeeIndices))
	for i := range committeeIndices {
		uintCommitteeIndices[i] = uint64(committeeIndices[i])
	}
	sigs, err := d.account.(e2wtypes.AccountProtectingMultiSigner).SignBeaconAttestations(ctx,
		uint64(slot),
		e2Accounts,
		uintCommitteeIndices,
		blockRoot[:],
		uint64(sourceEpoch),
		sourceRoot[:],
		uint64(targetEpoch),
		targetRoot[:],
		signatureDomain[:],
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign beacon attestation")
	}

	res := make([]spec.BLSSignature, len(sigs))
	for i := range sigs {
		if sigs[i] != nil {
			copy(res[i][:], sigs[i].Marshal())
		}
	}
	return res, nil
}

// SignAggregateAndProof signs an aggregate and proof item.
func (d *ValidatingAccount) SignAggregateAndProof(ctx context.Context, slot spec.Slot, aggregateAndProofRoot spec.Root) (spec.BLSSignature, error) {
	// Fetch the domain.
	domain, err := d.domainProvider.Domain(ctx,
		d.accountManager.aggregateAndProofDomainType,
		spec.Epoch(slot/d.accountManager.slotsPerEpoch))
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to obtain signature domain for beacon aggregate and proof")
	}

	sig, err := d.account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx, aggregateAndProofRoot[:], domain[:])
	if err != nil {
		return spec.BLSSignature{}, errors.Wrap(err, "failed to aggregate and proof")
	}

	var signature spec.BLSSignature
	copy(signature[:], sig.Marshal())
	return signature, nil
}
