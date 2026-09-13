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

package beaconblockproposal_test

import (
	"errors"
	"math"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	apiv1gloas "github.com/attestantio/go-eth2-client/api/v1/gloas"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/proposerpreferences"
	"github.com/attestantio/vouch/strategies/beaconblockproposal"
	"github.com/stretchr/testify/require"
)

type providerReadiness struct {
	ready    bool
	provider string
	slot     phase0.Slot
	index    phase0.ValidatorIndex
}

func (p *providerReadiness) ProviderReady(provider string, slot phase0.Slot, index phase0.ValidatorIndex) bool {
	p.provider = provider
	p.slot = slot
	p.index = index

	return p.ready
}

func gloasBlock(builderIndex gloas.BuilderIndex) *gloas.BeaconBlock {
	return &gloas.BeaconBlock{
		ProposerIndex: 7,
		Body: &gloas.BeaconBlockBody{
			SignedExecutionPayloadBid: &gloas.SignedExecutionPayloadBid{
				Message: &gloas.ExecutionPayloadBid{BuilderIndex: builderIndex, FeeRecipient: bellatrix.ExecutionAddress{0x01}},
			},
		},
	}
}

func withoutPayload(builderIndex gloas.BuilderIndex) *api.VersionedEPBSProposal {
	return &api.VersionedEPBSProposal{Version: spec.DataVersionGloas, Gloas: gloasBlock(builderIndex)}
}

func withPayload(builderIndex gloas.BuilderIndex) *api.VersionedEPBSProposal {
	return &api.VersionedEPBSProposal{
		Version:                  spec.DataVersionGloas,
		ExecutionPayloadIncluded: true,
		GloasContents:            &apiv1gloas.BlockContents{Block: gloasBlock(builderIndex)},
	}
}

func TestValidateEPBSProposalMatchesPayloadToAuctionResult(t *testing.T) {
	requested := true
	notRequested := false
	tests := []struct {
		name           string
		proposal       *api.VersionedEPBSProposal
		includePayload *bool
		err            string
	}{
		{
			name:           "BuilderBackedWithoutPayloadRequested",
			proposal:       withoutPayload(1),
			includePayload: &requested,
		},
		{
			name:     "BuilderBackedWithoutPayloadNotRequested",
			proposal: withoutPayload(1),
		},
		{
			name:           "BuilderBackedWithPayload",
			proposal:       withPayload(1),
			includePayload: &requested,
			err:            "builder-backed ePBS proposal carries an execution payload",
		},
		{
			name:           "BuilderBackedWithPayloadNotRequested",
			proposal:       withPayload(1),
			includePayload: &notRequested,
			err:            "builder-backed ePBS proposal carries an execution payload",
		},
		{
			name:           "SelfBuiltWithPayloadRequested",
			proposal:       withPayload(gloas.BuilderIndexSelfBuild),
			includePayload: &requested,
		},
		{
			name:           "SelfBuiltWithoutPayloadRequested",
			proposal:       withoutPayload(gloas.BuilderIndexSelfBuild),
			includePayload: &requested,
			err:            "ePBS proposal excludes requested execution payload",
		},
		{
			name:           "SelfBuiltWithoutPayloadNotRequested",
			proposal:       withoutPayload(gloas.BuilderIndexSelfBuild),
			includePayload: &notRequested,
		},
		{
			name:           "NotGloasWithoutPayloadRequested",
			proposal:       &api.VersionedEPBSProposal{Version: spec.DataVersionFulu},
			includePayload: &requested,
			err:            "ePBS proposal excludes requested execution payload",
		},
		{
			name:     "NotGloasNotRequested",
			proposal: &api.VersionedEPBSProposal{Version: spec.DataVersionFulu},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := beaconblockproposal.ValidateEPBSProposal(test.proposal, test.includePayload)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateEPBSProposalZeroFeeRecipient(t *testing.T) {
	infinity := phase0.BLSSignature{0xc0}
	tests := []struct {
		name   string
		mutate func(*gloas.SignedExecutionPayloadBid)
		err    string
	}{
		{
			name: "SelfBuild",
			mutate: func(bid *gloas.SignedExecutionPayloadBid) {
				bid.Signature = infinity
			},
		},
		{
			name: "BuilderBacked",
			mutate: func(bid *gloas.SignedExecutionPayloadBid) {
				bid.Message.BuilderIndex = 1
				bid.Signature = infinity
			},
			err: "beacon block obtained with 0 fee recipient",
		},
		{
			name: "SelfBuildNonZeroValue",
			mutate: func(bid *gloas.SignedExecutionPayloadBid) {
				bid.Message.Value = 1
				bid.Signature = infinity
			},
			err: "beacon block obtained with 0 fee recipient",
		},
		{
			name: "SelfBuildNonZeroExecutionPayment",
			mutate: func(bid *gloas.SignedExecutionPayloadBid) {
				bid.Message.ExecutionPayment = 1
				bid.Signature = infinity
			},
			err: "beacon block obtained with 0 fee recipient",
		},
		{
			name:   "SelfBuildNonInfinitySignature",
			mutate: func(*gloas.SignedExecutionPayloadBid) {},
			err:    "beacon block obtained with 0 fee recipient",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proposal := withoutPayload(gloas.BuilderIndexSelfBuild)
			signedBid := proposal.Gloas.Body.SignedExecutionPayloadBid
			signedBid.Message.FeeRecipient = bellatrix.ExecutionAddress{}
			test.mutate(signedBid)

			err := beaconblockproposal.ValidateEPBSProposal(proposal, nil)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateBuilderBidReadiness(t *testing.T) {
	tests := []struct {
		name      string
		readiness *providerReadiness
		proposal  *api.VersionedEPBSProposal
		err       string
		checked   bool
	}{
		{
			name:     "NoReadinessBuilder",
			proposal: withoutPayload(1),
			err:      "builder-backed ePBS proposal from provider without current preferences",
		},
		{
			name:     "NoReadinessSelfBuild",
			proposal: withoutPayload(gloas.BuilderIndexSelfBuild),
		},
		{
			name:      "NotGloas",
			readiness: &providerReadiness{},
			proposal:  &api.VersionedEPBSProposal{Version: spec.DataVersionFulu},
		},
		{
			name:      "SelfBuildUnready",
			readiness: &providerReadiness{},
			proposal:  withoutPayload(gloas.BuilderIndexSelfBuild),
		},
		{
			name:      "SelfBuildWithPayloadUnready",
			readiness: &providerReadiness{},
			proposal:  withPayload(gloas.BuilderIndexSelfBuild),
		},
		{
			name:      "BuilderReady",
			readiness: &providerReadiness{ready: true},
			proposal:  withoutPayload(1),
			checked:   true,
		},
		{
			name:      "BuilderUnready",
			readiness: &providerReadiness{},
			proposal:  withoutPayload(1),
			err:       "builder-backed ePBS proposal from provider without current preferences",
			checked:   true,
		},
		{
			name:      "BuilderWithPayloadUnready",
			readiness: &providerReadiness{},
			proposal:  withPayload(1),
			err:       "builder-backed ePBS proposal from provider without current preferences",
			checked:   true,
		},
		{
			name:      "BuilderBelowSelfBuildUnready",
			readiness: &providerReadiness{},
			proposal:  withoutPayload(gloas.BuilderIndex(math.MaxUint64 - 1)),
			err:       "builder-backed ePBS proposal from provider without current preferences",
			checked:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var readiness proposerpreferences.ProviderReadiness
			if test.readiness != nil {
				readiness = test.readiness
			}
			err := beaconblockproposal.ValidateBuilderBidReadiness(readiness, "node", 64, test.proposal)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
			if test.checked {
				require.Equal(t, "node", test.readiness.provider)
				require.Equal(t, phase0.Slot(64), test.readiness.slot)
				require.Equal(t, phase0.ValidatorIndex(7), test.readiness.index)
			} else if test.readiness != nil {
				require.Empty(t, test.readiness.provider)
			}
		})
	}
}

func TestBuilderIndexSelfBuildIsUint64Max(t *testing.T) {
	require.Equal(t, gloas.BuilderIndex(math.MaxUint64), gloas.BuilderIndexSelfBuild)
}

func TestRejectionReason(t *testing.T) {
	includePayload := true
	zeroFeeRecipient := withoutPayload(1)
	zeroFeeRecipient.Gloas.Body.SignedExecutionPayloadBid.Message.FeeRecipient = bellatrix.ExecutionAddress{}
	tests := []struct {
		name     string
		proposal *api.VersionedEPBSProposal
		reason   string
	}{
		{name: "Nil", reason: "empty_response"},
		{name: "Malformed", proposal: &api.VersionedEPBSProposal{Version: spec.DataVersionGloas}, reason: "malformed_proposal"},
		{name: "ZeroFeeRecipient", proposal: zeroFeeRecipient, reason: "zero_fee_recipient"},
		{name: "BuilderPayloadIncluded", proposal: withPayload(1), reason: "builder_payload_included"},
		{name: "RequestedPayloadMissing", proposal: withoutPayload(gloas.BuilderIndexSelfBuild), reason: "requested_payload_missing"},
		{name: "ProviderNotReady", proposal: withoutPayload(1), reason: "provider_preferences_not_ready"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := beaconblockproposal.ValidateEPBSProposal(test.proposal, &includePayload)
			if err == nil {
				err = beaconblockproposal.ValidateBuilderBidReadiness(&providerReadiness{}, "provider", 1, test.proposal)
			}
			require.Error(t, err)
			require.Equal(t, test.reason, beaconblockproposal.RejectionReason(err))
		})
	}
	require.Equal(t, "invalid_proposal", beaconblockproposal.RejectionReason(errors.New("other")))
}

func TestEPBSProposalSource(t *testing.T) {
	builderURL := map[string]any{"eth-builder-url": "https://builder.example"}
	tests := []struct {
		name     string
		proposal *api.VersionedEPBSProposal
		metadata map[string]any
		source   string
	}{
		{name: "PreGloas", proposal: &api.VersionedEPBSProposal{Version: spec.DataVersionFulu}, metadata: builderURL, source: "self_build"},
		{name: "SelfBuild", proposal: withPayload(gloas.BuilderIndexSelfBuild), metadata: builderURL, source: "self_build"},
		{name: "BuilderAPI", proposal: withoutPayload(1), metadata: builderURL, source: "builder_api"},
		{name: "P2PBuilder", proposal: withoutPayload(1), source: "p2p_builder"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.source, beaconblockproposal.EPBSProposalSource(test.proposal, test.metadata))
		})
	}
}
