// Copyright © 2026 Attestant Limited.
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

// Package beaconblockproposal provides validation shared by proposal selection and publication.
package beaconblockproposal

import (
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/proposerpreferences"
	"github.com/pkg/errors"
)

// ValidateEPBSProposal confirms that an ePBS proposal is usable.  A requested execution payload
// is required only of a self-built Gloas proposal, and a builder-backed one must not carry it.
func ValidateEPBSProposal(proposal *api.VersionedEPBSProposal, includePayload *bool) error {
	if proposal == nil {
		return errors.New("beacon node returned no ePBS proposal")
	}
	payloadRequested := includePayload != nil && *includePayload
	if proposal.Version != spec.DataVersionGloas {
		if payloadRequested && !proposal.ExecutionPayloadIncluded {
			return errors.New("ePBS proposal excludes requested execution payload")
		}

		return nil
	}

	signedBid, err := EPBSProposalBid(proposal)
	if err != nil {
		return err
	}
	bid := signedBid.Message
	// A self-built bid pays nothing, so it may leave its fee recipient unset.  The payload
	// envelope's own fee recipient is checked before signing.
	selfBuiltWithoutPayment := bid.BuilderIndex == gloas.BuilderIndexSelfBuild &&
		bid.Value == 0 &&
		bid.ExecutionPayment == 0 &&
		signedBid.Signature.IsInfinity()
	if bid.FeeRecipient.IsZero() && !selfBuiltWithoutPayment {
		return errors.New("beacon block obtained with 0 fee recipient")
	}

	return validateEPBSPayload(bid.BuilderIndex, proposal.ExecutionPayloadIncluded, payloadRequested)
}

// EPBSProposalBid returns the signed execution payload bid of a Gloas proposal.
func EPBSProposalBid(proposal *api.VersionedEPBSProposal) (*gloas.SignedExecutionPayloadBid, error) {
	block := proposal.Gloas
	if proposal.ExecutionPayloadIncluded {
		if proposal.GloasContents == nil {
			return nil, errors.New("ePBS proposal has no execution payload bid")
		}
		block = proposal.GloasContents.Block
	}
	if block == nil || block.Body == nil || block.Body.SignedExecutionPayloadBid == nil || block.Body.SignedExecutionPayloadBid.Message == nil {
		return nil, errors.New("ePBS proposal has no execution payload bid")
	}

	return block.Body.SignedExecutionPayloadBid, nil
}

// validateEPBSPayload matches a Gloas proposal's payload to its auction result.  The beacon node
// cannot return a builder's payload, so only a self-built proposal can carry the requested one.
func validateEPBSPayload(builderIndex gloas.BuilderIndex, payloadIncluded bool, payloadRequested bool) error {
	if builderIndex != gloas.BuilderIndexSelfBuild {
		if payloadIncluded {
			return errors.New("builder-backed ePBS proposal carries an execution payload")
		}

		return nil
	}
	if payloadRequested && !payloadIncluded {
		return errors.New("ePBS proposal excludes requested execution payload")
	}

	return nil
}

// ValidateBuilderBidReadiness rejects a builder-backed Gloas proposal from a provider that has not
// accepted the current proposer preferences.  Self-built proposals are always accepted.
// Without readiness no provider is ready, so builder-backed proposals are rejected.
// The proposal must already have passed ValidateEPBSProposal.
func ValidateBuilderBidReadiness(readiness proposerpreferences.ProviderReadiness,
	provider string,
	slot phase0.Slot,
	proposal *api.VersionedEPBSProposal,
) error {
	if proposal.Version != spec.DataVersionGloas {
		return nil
	}
	block := proposal.Gloas
	if proposal.ExecutionPayloadIncluded {
		block = proposal.GloasContents.Block
	}
	if block.Body.SignedExecutionPayloadBid.Message.BuilderIndex == gloas.BuilderIndexSelfBuild {
		return nil
	}
	if readiness == nil || !readiness.ProviderReady(provider, slot, block.ProposerIndex) {
		return errors.New("builder-backed ePBS proposal from provider without current preferences")
	}

	return nil
}
