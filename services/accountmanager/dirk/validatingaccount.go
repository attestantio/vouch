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
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// ValidatingAccount is a wrapper around the dirk account that implements ValidatingAccount.
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
	span, ctx := opentracing.StartSpanFromContext(ctx, "dirk.SignSlotSelection")
	defer span.Finish()

	// Calculate the signature domain.
	signatureDomain, err := d.signatureDomainProvider.SignatureDomain(ctx,
		d.accountManager.selectionProofDomain,
		slot/d.accountManager.slotsPerEpoch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for selection proof")
	}

	slotBytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(slotBytes, slot)

	sig, err := d.account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx, slotBytes, signatureDomain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign slot")
	}
	return sig.Marshal(), nil
}

// SignRANDAOReveal returns a RANDAO reveal signature.
// This signs an epoch with the "RANDAO reveal" domain.
// N.B. This passes in a slot, not an epoch.
func (d *ValidatingAccount) SignRANDAOReveal(ctx context.Context, slot uint64) ([]byte, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "dirk.SignRANDAOReveal")
	defer span.Finish()

	epoch := slot / d.accountManager.slotsPerEpoch
	// Obtain the RANDAO reveal signature domain.
	signatureDomain, err := d.signatureDomainProvider.SignatureDomain(ctx,
		d.accountManager.randaoDomain,
		epoch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for RANDAO reveal")
	}

	epochBytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(epochBytes, epoch)

	sig, err := d.account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx, epochBytes, signatureDomain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign RANDO reveal")
	}
	return sig.Marshal(), nil
}

// SignBeaconBlockProposal signs a beacon block proposal item.
func (d *ValidatingAccount) SignBeaconBlockProposal(ctx context.Context,
	slot uint64,
	proposerIndex uint64,
	parentRoot []byte,
	stateRoot []byte,
	bodyRoot []byte) ([]byte, error) {

	// Fetch the signature domain.
	signatureDomain, err := d.signatureDomainProvider.SignatureDomain(ctx,
		d.accountManager.beaconProposerDomain,
		slot/d.accountManager.slotsPerEpoch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for beacon proposal")
	}

	sig, err := d.account.(e2wtypes.AccountProtectingSigner).SignBeaconProposal(ctx,
		slot,
		proposerIndex,
		parentRoot,
		stateRoot,
		bodyRoot,
		signatureDomain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign beacon block proposal")
	}
	return sig.Marshal(), nil
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
	span, ctx := opentracing.StartSpanFromContext(ctx, "dirk.SignBeaconAttestation")
	defer span.Finish()

	signatureDomain, err := d.signatureDomainProvider.SignatureDomain(ctx,
		d.accountManager.beaconAttesterDomain,
		slot/d.accountManager.slotsPerEpoch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for beacon attestation")
	}

	sig, err := d.account.(e2wtypes.AccountProtectingSigner).SignBeaconAttestation(ctx,
		slot,
		committeeIndex,
		blockRoot,
		sourceEpoch,
		sourceRoot,
		targetEpoch,
		targetRoot,
		signatureDomain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign beacon attestation")
	}
	return sig.Marshal(), nil
}

// SignBeaconAttestations signs multiple beacon attestations.
func (d *ValidatingAccount) SignBeaconAttestations(ctx context.Context,
	slot uint64,
	accounts []accountmanager.ValidatingAccount,
	committeeIndices []uint64,
	blockRoot []byte,
	sourceEpoch uint64,
	sourceRoot []byte,
	targetEpoch uint64,
	targetRoot []byte) ([][]byte, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "dirk.SignBeaconAttestations")
	defer span.Finish()

	signatureDomain, err := d.signatureDomainProvider.SignatureDomain(ctx,
		d.accountManager.beaconAttesterDomain,
		slot/d.accountManager.slotsPerEpoch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for beacon attestation")
	}

	e2Accounts := make([]e2wtypes.Account, len(accounts))
	for i := range accounts {
		e2Accounts[i] = accounts[i].(*ValidatingAccount).account
	}
	sigs, err := d.account.(e2wtypes.AccountProtectingMultiSigner).SignBeaconAttestations(ctx,
		slot,
		e2Accounts,
		committeeIndices,
		blockRoot,
		sourceEpoch,
		sourceRoot,
		targetEpoch,
		targetRoot,
		signatureDomain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign beacon attestation")
	}

	res := make([][]byte, len(sigs))
	for i := range sigs {
		if sigs[i] != nil {
			res[i] = sigs[i].Marshal()
		}
	}
	return res, nil
}

// SignAggregateAndProof signs an aggregate and proof item.
func (d *ValidatingAccount) SignAggregateAndProof(ctx context.Context, slot uint64, aggregateAndProofRoot []byte) ([]byte, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "dirk.SignAggregateAndProof")
	defer span.Finish()

	// Fetch the signature domain.
	signatureDomain, err := d.signatureDomainProvider.SignatureDomain(ctx,
		d.accountManager.aggregateAndProofDomain,
		slot)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature domain for beacon aggregate and proof")
	}

	sig, err := d.account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx, aggregateAndProofRoot, signatureDomain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to aggregate and proof")
	}
	return sig.Marshal(), nil
}
