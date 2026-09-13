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

package standard_test

import (
	"context"
	"math"
	"testing"

	consensusapi "github.com/attestantio/go-eth2-client/api"
	mockconsensusclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/beaconblockproposer/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// TestProposeGloasSendsConfiguredBuilderConfig proves that the proposer resolves the
// validator's ePBS policy, binds direct-builder authorization to the proposal slot and
// sends the resulting non-nil config with a self-built request.
func TestProposeGloasSendsConfiguredBuilderConfig(t *testing.T) {
	ctx := context.Background()

	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	responseClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	var epbsOpts *consensusapi.EPBSProposalOpts
	proposalClient.EPBSProposalFunc = func(ctx context.Context, opts *consensusapi.EPBSProposalOpts) (*consensusapi.Response[*consensusapi.VersionedEPBSProposal], error) {
		epbsOpts = opts
		response, err := responseClient.EPBSProposal(ctx, opts)
		require.NoError(t, err)
		response.Data.GloasContents.KZGProofs = []deneb.KZGProof{}
		response.Data.GloasContents.Blobs = []deneb.Blob{}
		setSelfBuildProposal(t, response.Data)
		blockRoot, err := response.Data.GloasContents.Block.HashTreeRoot()
		require.NoError(t, err)
		response.Data.GloasContents.ExecutionPayloadEnvelope.BeaconBlockRoot = blockRoot

		return response, nil
	}

	signer := mocksigner.New()
	authSigner := &capturingBuilderRequestAuthSigner{signature: phase0.BLSSignature{0x04}}
	executionConfigProvider := &recordingExecutionConfigProvider{config: &beaconblockproposer.ProposerConfig{
		EPBSBuilderConfig: &beaconblockproposer.EPBSBuilderConfig{
			MinBid:             12345,
			BuilderBoostFactor: 100,
			Builders: []*beaconblockproposer.EPBSBuilder{{
				URL:                 "https://builder.example",
				AuthData:            []byte{0x12, 0x34},
				BuilderPubkeys:      []phase0.BLSPubKey{{0x05}},
				MaxExecutionPayment: 6,
				MinBid:              7,
				BuilderBoostFactor:  80,
			}},
		},
	}}
	proposalSubmitter := &capturingProposalSubmitter{}
	blockSigner := &capturingBeaconBlockSigner{signature: phase0.BLSSignature{0x01}}
	envelopeSigner := &capturingExecutionPayloadEnvelopeSigner{signature: phase0.BLSSignature{0x03}}
	envelopeSubmitter := &capturingExecutionPayloadEnvelopeSubmitter{}
	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithProposalDataProvider(proposalClient),
		standard.WithExecutionConfigProvider(executionConfigProvider),
		standard.WithChainTime(&forkChainTime{}),
		standard.WithValidatingAccountsProvider(mockaccountmanager.NewValidatingAccountsProvider()),
		standard.WithProposalSubmitter(proposalSubmitter),
		standard.WithRANDAORevealSigner(signer),
		standard.WithBeaconBlockSigner(blockSigner),
		standard.WithBuilderRequestAuthSigner(authSigner),
		standard.WithExecutionPayloadEnvelopeSigner(envelopeSigner),
		standard.WithExecutionPayloadEnvelopeSubmitter(envelopeSubmitter),
		standard.WithBlobSidecarSigner(signer),
	)
	require.NoError(t, err)

	duty := beaconblockproposer.NewDuty(1, 0)
	duty.SetAccount(&testAccount{})
	duty.SetRandaoReveal(phase0.BLSSignature{0x02})

	require.NoError(t, service.Propose(ctx, duty))

	require.NotNil(t, epbsOpts)
	require.NotNil(t, epbsOpts.IncludePayload)
	require.True(t, *epbsOpts.IncludePayload)
	require.NotNil(t, epbsOpts.BuilderConfig)
	require.Equal(t, phase0.Gwei(12345), epbsOpts.BuilderConfig.MinBid)
	require.Equal(t, uint64(100), epbsOpts.BuilderConfig.BuilderBoostFactor)
	require.Len(t, epbsOpts.BuilderConfig.Builders, 1)
	require.Equal(t, []byte("https://builder.example"), epbsOpts.BuilderConfig.Builders[0].URL)
	require.Equal(t, []phase0.BLSPubKey{{0x05}}, epbsOpts.BuilderConfig.Builders[0].BuilderPubkeys)
	require.Equal(t, phase0.Gwei(6), epbsOpts.BuilderConfig.Builders[0].MaxExecutionPayment)
	require.Equal(t, phase0.Gwei(7), epbsOpts.BuilderConfig.Builders[0].MinBid)
	require.Equal(t, uint64(80), epbsOpts.BuilderConfig.Builders[0].BuilderBoostFactor)
	require.Equal(t, phase0.Slot(1), epbsOpts.BuilderConfig.Builders[0].Auth.Message.Slot)
	require.Equal(t, []byte{0x12, 0x34}, epbsOpts.BuilderConfig.Builders[0].Auth.Message.Data)
	require.Equal(t, phase0.BLSSignature{0x04}, epbsOpts.BuilderConfig.Builders[0].Auth.Signature)
	require.Equal(t, phase0.Slot(1), authSigner.auth.Slot)
	require.Equal(t, []byte{0x12, 0x34}, authSigner.auth.Data)
	jsonEncoded, err := epbsOpts.BuilderConfig.MarshalJSON()
	require.NoError(t, err)
	var jsonDecoded gloas.BuilderConfig
	require.NoError(t, jsonDecoded.UnmarshalJSON(jsonEncoded))
	require.Equal(t, epbsOpts.BuilderConfig, &jsonDecoded)
	sszEncoded, err := epbsOpts.BuilderConfig.MarshalSSZ()
	require.NoError(t, err)
	var sszDecoded gloas.BuilderConfig
	require.NoError(t, sszDecoded.UnmarshalSSZ(sszEncoded))
	require.Equal(t, epbsOpts.BuilderConfig, &sszDecoded)
	require.Equal(t, 1, authSigner.calls)
	require.Equal(t, 1, executionConfigProvider.calls)
	require.Equal(t, 1, blockSigner.calls)
	require.Equal(t, 1, envelopeSigner.calls)
	require.Equal(t, 1, proposalSubmitter.calls)
	require.Equal(t, 1, envelopeSubmitter.calls)
}

type recordingExecutionConfigProvider struct {
	config *beaconblockproposer.ProposerConfig
	err    error
	calls  int
}

func (p *recordingExecutionConfigProvider) ProposerConfig(_ context.Context, _ e2wtypes.Account, _ phase0.BLSPubKey) (*beaconblockproposer.ProposerConfig, error) {
	p.calls++

	return p.config, p.err
}

type capturingBuilderRequestAuthSigner struct {
	auth      *gloas.BuilderRequestAuth
	signature phase0.BLSSignature
	calls     int
}

func (s *capturingBuilderRequestAuthSigner) SignBuilderRequestAuth(_ context.Context, _ e2wtypes.Account, auth *gloas.BuilderRequestAuth) (phase0.BLSSignature, error) {
	s.calls++
	s.auth = auth

	return s.signature, nil
}

// TestProposeGloasBuilderBackedPublishesBlockOnly proves that a proposal the beacon node
// awarded to a P2P builder is a complete duty on its own: Vouch signs and publishes the
// block, and does no envelope work, because the builder reveals the payload itself.
func TestProposeGloasBuilderBackedPublishesBlockOnly(t *testing.T) {
	ctx := context.Background()

	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	responseClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	var responseProposal *consensusapi.VersionedEPBSProposal
	proposalClient.EPBSProposalFunc = func(ctx context.Context, opts *consensusapi.EPBSProposalOpts) (*consensusapi.Response[*consensusapi.VersionedEPBSProposal], error) {
		response, err := responseClient.EPBSProposal(ctx, builderBackedOpts(opts))
		require.NoError(t, err)
		setBuilderBackedProposal(t, response.Data, 7)
		responseProposal = response.Data

		return response, nil
	}

	signer := mocksigner.New()
	proposalSubmitter := &capturingProposalSubmitter{}
	blockSigner := &capturingBeaconBlockSigner{signature: phase0.BLSSignature{0x01}}
	envelopeSigner := &capturingExecutionPayloadEnvelopeSigner{signature: phase0.BLSSignature{0x03}}
	envelopeSubmitter := &capturingExecutionPayloadEnvelopeSubmitter{}
	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithProposalDataProvider(proposalClient),
		standard.WithExecutionConfigProvider(&recordingExecutionConfigProvider{config: &beaconblockproposer.ProposerConfig{
			FeeRecipient: bellatrix.ExecutionAddress{0x07},
		}}),
		standard.WithChainTime(&forkChainTime{}),
		standard.WithValidatingAccountsProvider(mockaccountmanager.NewValidatingAccountsProvider()),
		standard.WithProposalSubmitter(proposalSubmitter),
		standard.WithRANDAORevealSigner(signer),
		standard.WithBeaconBlockSigner(blockSigner),
		standard.WithExecutionPayloadEnvelopeSigner(envelopeSigner),
		standard.WithExecutionPayloadEnvelopeSubmitter(envelopeSubmitter),
		standard.WithBlobSidecarSigner(signer),
	)
	require.NoError(t, err)

	duty := beaconblockproposer.NewDuty(1, 0)
	duty.SetAccount(&testAccount{})
	duty.SetRandaoReveal(phase0.BLSSignature{0x02})

	require.NoError(t, service.Propose(ctx, duty))

	require.Equal(t, 1, proposalSubmitter.calls)
	require.NotNil(t, proposalSubmitter.proposal)
	require.NotNil(t, proposalSubmitter.proposal.Gloas)
	require.Same(t, responseProposal.Gloas, proposalSubmitter.proposal.Gloas.Message)
	require.Equal(t, phase0.BLSSignature{0x01}, proposalSubmitter.proposal.Gloas.Signature)
	require.Equal(t, *responseProposal.BeaconBlockBodyRoot, blockSigner.bodyRoot)
	require.Equal(t, 1, blockSigner.calls)
	require.Zero(t, envelopeSigner.calls)
	require.Zero(t, envelopeSubmitter.calls)
	require.Nil(t, envelopeSubmitter.opts)
}

// TestProposeGloasSelfBuiltWithoutPayloadFails proves that a self-built proposal that
// arrives without the payload envelope Vouch asked for fails the duty: the envelope stayed
// cached on the producing node, so nothing here can reveal the payload.
func TestProposeGloasSelfBuiltWithoutPayloadFails(t *testing.T) {
	ctx := context.Background()

	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	responseClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	proposalClient.EPBSProposalFunc = func(ctx context.Context, opts *consensusapi.EPBSProposalOpts) (*consensusapi.Response[*consensusapi.VersionedEPBSProposal], error) {
		response, err := responseClient.EPBSProposal(ctx, builderBackedOpts(opts))
		require.NoError(t, err)
		bid := response.Data.Gloas.Body.SignedExecutionPayloadBid.Message
		bid.BuilderIndex = gloas.BuilderIndex(math.MaxUint64)
		bid.FeeRecipient = bellatrix.ExecutionAddress{0x07}

		return response, nil
	}

	signer := mocksigner.New()
	proposalSubmitter := &capturingProposalSubmitter{}
	blockSigner := &capturingBeaconBlockSigner{signature: phase0.BLSSignature{0x01}}
	envelopeSigner := &capturingExecutionPayloadEnvelopeSigner{signature: phase0.BLSSignature{0x03}}
	envelopeSubmitter := &capturingExecutionPayloadEnvelopeSubmitter{}
	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithProposalDataProvider(proposalClient),
		standard.WithChainTime(&forkChainTime{}),
		standard.WithValidatingAccountsProvider(mockaccountmanager.NewValidatingAccountsProvider()),
		standard.WithProposalSubmitter(proposalSubmitter),
		standard.WithRANDAORevealSigner(signer),
		standard.WithBeaconBlockSigner(blockSigner),
		standard.WithExecutionPayloadEnvelopeSigner(envelopeSigner),
		standard.WithExecutionPayloadEnvelopeSubmitter(envelopeSubmitter),
		standard.WithBlobSidecarSigner(signer),
	)
	require.NoError(t, err)

	duty := beaconblockproposer.NewDuty(1, 0)
	duty.SetAccount(&testAccount{})
	duty.SetRandaoReveal(phase0.BLSSignature{0x02})

	require.EqualError(t, service.Propose(ctx, duty),
		"failed to propose block: ePBS proposal excludes requested execution payload")
	require.Zero(t, blockSigner.calls)
	require.Zero(t, envelopeSigner.calls)
	require.Zero(t, proposalSubmitter.calls)
	require.Zero(t, envelopeSubmitter.calls)
}

// TestProposeGloasRejectsInconsistentProposals proves that a proposal whose metadata does
// not hold together is rejected before anything is signed, whichever arm it arrives on.
func TestProposeGloasRejectsInconsistentProposals(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		mutate  func(*testing.T, *consensusapi.VersionedEPBSProposal)
		version spec.DataVersion
		err     string
	}{
		{
			name: "BidForIncorrectSlot",
			mutate: func(_ *testing.T, proposal *consensusapi.VersionedEPBSProposal) {
				proposal.Gloas.Body.SignedExecutionPayloadBid.Message.Slot++
			},
			err: "failed to propose block: ePBS execution payload bid for incorrect slot",
		},
		{
			name: "BidForIncorrectParentBlock",
			mutate: func(_ *testing.T, proposal *consensusapi.VersionedEPBSProposal) {
				proposal.Gloas.Body.SignedExecutionPayloadBid.Message.ParentBlockRoot[0] ^= 0xff
			},
			err: "failed to propose block: ePBS execution payload bid for incorrect parent block",
		},
		{
			name: "BidForIncorrectFeeRecipient",
			mutate: func(_ *testing.T, proposal *consensusapi.VersionedEPBSProposal) {
				proposal.Gloas.Body.SignedExecutionPayloadBid.Message.FeeRecipient = bellatrix.ExecutionAddress{0x08}
			},
			err: "failed to propose block: ePBS execution payload bid for incorrect fee recipient",
		},
		{
			name: "PreGloasVersion",
			mutate: func(_ *testing.T, proposal *consensusapi.VersionedEPBSProposal) {
				proposal.Version = spec.DataVersionElectra
			},
			err: "failed to propose block: failed to obtain ePBS proposal slot: no epbs proposal in electra",
		},
		{
			name: "MissingBlock",
			mutate: func(_ *testing.T, proposal *consensusapi.VersionedEPBSProposal) {
				proposal.Gloas.Body.SignedExecutionPayloadBid = nil
			},
			err: "failed to propose block: ePBS proposal has no execution payload bid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proposalClient, err := mockconsensusclient.New(ctx)
			require.NoError(t, err)
			responseClient, err := mockconsensusclient.New(ctx)
			require.NoError(t, err)
			proposalClient.EPBSProposalFunc = func(ctx context.Context, opts *consensusapi.EPBSProposalOpts) (*consensusapi.Response[*consensusapi.VersionedEPBSProposal], error) {
				response, err := responseClient.EPBSProposal(ctx, builderBackedOpts(opts))
				require.NoError(t, err)
				setBuilderBackedProposal(t, response.Data, 7)
				test.mutate(t, response.Data)

				return response, nil
			}

			signer := mocksigner.New()
			proposalSubmitter := &capturingProposalSubmitter{}
			blockSigner := &capturingBeaconBlockSigner{signature: phase0.BLSSignature{0x01}}
			envelopeSigner := &capturingExecutionPayloadEnvelopeSigner{signature: phase0.BLSSignature{0x03}}
			envelopeSubmitter := &capturingExecutionPayloadEnvelopeSubmitter{}
			service, err := standard.New(ctx,
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithProposalDataProvider(proposalClient),
				standard.WithExecutionConfigProvider(&recordingExecutionConfigProvider{config: &beaconblockproposer.ProposerConfig{
					FeeRecipient: bellatrix.ExecutionAddress{0x07},
				}}),
				standard.WithChainTime(&forkChainTime{}),
				standard.WithValidatingAccountsProvider(mockaccountmanager.NewValidatingAccountsProvider()),
				standard.WithProposalSubmitter(proposalSubmitter),
				standard.WithRANDAORevealSigner(signer),
				standard.WithBeaconBlockSigner(blockSigner),
				standard.WithExecutionPayloadEnvelopeSigner(envelopeSigner),
				standard.WithExecutionPayloadEnvelopeSubmitter(envelopeSubmitter),
				standard.WithBlobSidecarSigner(signer),
			)
			require.NoError(t, err)

			duty := beaconblockproposer.NewDuty(1, 0)
			duty.SetAccount(&testAccount{})
			duty.SetRandaoReveal(phase0.BLSSignature{0x02})

			require.EqualError(t, service.Propose(ctx, duty), test.err)
			require.Zero(t, blockSigner.calls)
			require.Zero(t, envelopeSigner.calls)
			require.Zero(t, proposalSubmitter.calls)
			require.Zero(t, envelopeSubmitter.calls)
		})
	}
}

// builderBackedOpts copies opts with the payload excluded, as a beacon node that awarded
// the slot to a P2P builder responds however the payload was requested.
func builderBackedOpts(opts *consensusapi.EPBSProposalOpts) *consensusapi.EPBSProposalOpts {
	excluded := false
	responseOpts := *opts
	responseOpts.IncludePayload = &excluded

	return &responseOpts
}

// setBuilderBackedProposal marks a mock proposal as won by the given P2P builder and gives
// its bid a fee recipient, which the mock leaves zero and Vouch rejects.  The retained body
// root is recalculated so that the proposal is signed over the block it now describes.
func setBuilderBackedProposal(t *testing.T, proposal *consensusapi.VersionedEPBSProposal, builderIndex gloas.BuilderIndex) {
	t.Helper()

	require.NotNil(t, proposal.Gloas)
	bid := proposal.Gloas.Body.SignedExecutionPayloadBid.Message
	bid.BuilderIndex = builderIndex
	bid.FeeRecipient = bellatrix.ExecutionAddress{0x07}
	proposal.BuilderIndex = &builderIndex
	bodyRoot, err := proposal.Gloas.Body.HashTreeRoot()
	require.NoError(t, err)
	retainedBodyRoot := phase0.Root(bodyRoot)
	proposal.BeaconBlockBodyRoot = &retainedBodyRoot
}
