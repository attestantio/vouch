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
	"errors"
	"testing"
	"time"

	mockblockauctioneer "github.com/attestantio/go-block-relay/services/blockauctioneer/mock"
	consensusapi "github.com/attestantio/go-eth2-client/api"
	mockconsensusclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/beaconblockproposer/standard"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	"github.com/attestantio/vouch/services/chaintime"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/signer"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestProposeGloas(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name                     string
		executionPayloadIncluded bool
		blockAuctioneer          bool
		builderBoostFactor       uint64
		proposerIndexMismatch    bool
		envelopeRootMismatch     bool
		envelopeSignerErr        error
		err                      string
	}{
		{
			name:                     "PayloadIncluded",
			executionPayloadIncluded: true,
			builderBoostFactor:       100,
		},
		{
			name:                     "ConfiguredAuctioneer",
			executionPayloadIncluded: true,
			blockAuctioneer:          true,
		},
		{
			name:                     "MismatchedProposerIndex",
			executionPayloadIncluded: true,
			proposerIndexMismatch:    true,
			err:                      "failed to propose block: ePBS proposal data for incorrect proposer index",
		},
		{
			name:                     "PayloadExcluded",
			executionPayloadIncluded: false,
			err:                      "failed to propose block: ePBS proposal excludes requested execution payload",
		},
		{
			name:                     "MismatchedEnvelopeRoot",
			executionPayloadIncluded: true,
			envelopeRootMismatch:     true,
			err:                      "failed to propose block: ePBS execution payload envelope is for incorrect block",
		},
		{
			name:                     "EnvelopeSigningFailure",
			executionPayloadIncluded: true,
			envelopeSignerErr:        errors.New("envelope signing failed"),
			err:                      "failed to propose block: failed to sign execution payload envelope: envelope signing failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			proposalClient, err := mockconsensusclient.New(ctx)
			require.NoError(t, err)
			proposalClient.ProposalFunc = func(context.Context, *consensusapi.ProposalOpts) (*consensusapi.Response[*consensusapi.VersionedProposal], error) {
				return nil, errors.New("legacy proposal endpoint called")
			}
			responseClient, err := mockconsensusclient.New(ctx)
			require.NoError(t, err)
			var epbsOpts *consensusapi.EPBSProposalOpts
			var responseProposal *consensusapi.VersionedEPBSProposal
			proposalClient.EPBSProposalFunc = func(ctx context.Context, opts *consensusapi.EPBSProposalOpts) (*consensusapi.Response[*consensusapi.VersionedEPBSProposal], error) {
				epbsOpts = opts
				responseOpts := *opts
				responseOpts.IncludePayload = &test.executionPayloadIncluded

				response, err := responseClient.EPBSProposal(ctx, &responseOpts)
				if err == nil && response.Data.ExecutionPayloadIncluded {
					if test.proposerIndexMismatch {
						response.Data.GloasContents.Block.ProposerIndex++
					}
					response.Data.GloasContents.KZGProofs = []deneb.KZGProof{{0x04}}
					response.Data.GloasContents.Blobs = []deneb.Blob{{0x05}}
					blockRoot, err := response.Data.GloasContents.Block.HashTreeRoot()
					require.NoError(t, err)
					response.Data.GloasContents.ExecutionPayloadEnvelope.BeaconBlockRoot = blockRoot
					if test.envelopeRootMismatch {
						response.Data.GloasContents.ExecutionPayloadEnvelope.BeaconBlockRoot[0] ^= 0xff
					}
				}
				if err == nil {
					responseProposal = response.Data
				}
				return response, err
			}

			proposalSubmitter := &capturingProposalSubmitter{}
			signer := mocksigner.New()
			signature := phase0.BLSSignature{0x01}
			blockSigner := &capturingBeaconBlockSigner{signature: signature}
			envelopeSignature := phase0.BLSSignature{0x03}
			envelopeSigner := &capturingExecutionPayloadEnvelopeSigner{signature: envelopeSignature, err: test.envelopeSignerErr}
			envelopeSubmitter := &capturingExecutionPayloadEnvelopeSubmitter{}

			params := []standard.Parameter{
				standard.WithLogLevel(zerolog.TraceLevel),
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
				standard.WithBuilderBoostFactor(test.builderBoostFactor),
			}
			if test.blockAuctioneer {
				cacheService := mockcache.New(map[phase0.Root]phase0.Slot{})
				params = append(params,
					standard.WithBlockAuctioneer(mockblockauctioneer.New()),
					standard.WithExecutionChainHeadProvider(cacheService.(cache.ExecutionChainHeadProvider)),
				)
			}
			service, err := standard.New(ctx, params...)
			require.NoError(t, err)

			duty := beaconblockproposer.NewDuty(1, 0)
			duty.SetAccount(&testAccount{})
			duty.SetRandaoReveal(phase0.BLSSignature{0x02})

			err = service.Propose(ctx, duty)
			if test.builderBoostFactor != 0 {
				capture.AssertHasEntry(t, "Ignoring non-default builder boost factor on Gloas proposal path")
			}
			if test.blockAuctioneer {
				capture.AssertHasEntry(t, "Ignoring configured block auctioneer on Gloas proposal path")
			}
			require.NotNil(t, epbsOpts)
			require.NotNil(t, epbsOpts.IncludePayload)
			require.True(t, *epbsOpts.IncludePayload)
			require.NotNil(t, epbsOpts.BuilderBoostFactor)
			require.Equal(t, uint64(0), *epbsOpts.BuilderBoostFactor)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				require.Nil(t, proposalSubmitter.proposal)
				require.Zero(t, proposalSubmitter.calls)
				if test.envelopeRootMismatch {
					require.Zero(t, blockSigner.calls)
					require.Zero(t, envelopeSigner.calls)
					require.Nil(t, envelopeSubmitter.opts)
				}
				if test.proposerIndexMismatch {
					require.Zero(t, blockSigner.calls)
					require.Zero(t, envelopeSigner.calls)
					require.Nil(t, envelopeSubmitter.opts)
				}
				if test.envelopeSignerErr != nil {
					require.Equal(t, 1, blockSigner.calls)
					require.Equal(t, 1, envelopeSigner.calls)
					require.Same(t, responseProposal.GloasContents.ExecutionPayloadEnvelope, envelopeSigner.envelope)
					require.Nil(t, envelopeSubmitter.opts)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, proposalSubmitter.proposal)
				require.NotNil(t, proposalSubmitter.proposal.Gloas)
				require.Equal(t, signature, proposalSubmitter.proposal.Gloas.Signature)
				require.Same(t, responseProposal.GloasContents.Block, proposalSubmitter.proposal.Gloas.Message)
				require.Same(t, responseProposal.GloasContents.ExecutionPayloadEnvelope, envelopeSigner.envelope)
				require.NotNil(t, envelopeSubmitter.opts)
				require.Equal(t, envelopeSignature, envelopeSubmitter.opts.SignedExecutionPayloadEnvelope.Gloas.Signature)
				require.Same(t, responseProposal.GloasContents.ExecutionPayloadEnvelope, envelopeSubmitter.opts.SignedExecutionPayloadEnvelope.Gloas.Message)
				require.NotEmpty(t, responseProposal.GloasContents.KZGProofs)
				require.NotEmpty(t, responseProposal.GloasContents.Blobs)
				require.Equal(t, responseProposal.GloasContents.KZGProofs, envelopeSubmitter.opts.KZGProofs)
				require.Equal(t, responseProposal.GloasContents.Blobs, envelopeSubmitter.opts.Blobs)
			}
		})
	}
}

func TestProposePreGloas(t *testing.T) {
	ctx := context.Background()

	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	responseClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	proposalClient.ProposalFunc = responseClient.Proposal
	proposalClient.EPBSProposalFunc = func(context.Context, *consensusapi.EPBSProposalOpts) (*consensusapi.Response[*consensusapi.VersionedEPBSProposal], error) {
		return nil, errors.New("ePBS proposal endpoint called")
	}

	proposalSubmitter := &capturingProposalSubmitter{}
	signer := mocksigner.New()
	blockSigner := &capturingBeaconBlockSigner{signature: phase0.BLSSignature{0x01}}
	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithProposalDataProvider(proposalClient),
		standard.WithChainTime(&forkChainTime{gloasForkEpoch: 1}),
		standard.WithValidatingAccountsProvider(mockaccountmanager.NewValidatingAccountsProvider()),
		standard.WithProposalSubmitter(proposalSubmitter),
		standard.WithRANDAORevealSigner(signer),
		standard.WithBeaconBlockSigner(blockSigner),
		standard.WithBlobSidecarSigner(signer),
	)
	require.NoError(t, err)

	duty := beaconblockproposer.NewDuty(1, 2)
	duty.SetAccount(&testAccount{})
	duty.SetRandaoReveal(phase0.BLSSignature{0x02})

	require.NoError(t, service.Propose(ctx, duty))
	require.NotNil(t, proposalSubmitter.proposal)
	require.Nil(t, proposalSubmitter.proposal.Gloas)
}

type capturingProposalSubmitter struct {
	proposal *consensusapi.VersionedSignedProposal
	calls    int
}

func (s *capturingProposalSubmitter) SubmitProposal(_ context.Context, proposal *consensusapi.VersionedSignedProposal) error {
	s.calls++
	s.proposal = proposal

	return nil
}

var _ submitter.ProposalSubmitter = (*capturingProposalSubmitter)(nil)

type capturingBeaconBlockSigner struct {
	signature phase0.BLSSignature
	calls     int
}

type capturingExecutionPayloadEnvelopeSigner struct {
	signature phase0.BLSSignature
	envelope  *gloas.ExecutionPayloadEnvelope
	calls     int
	err       error
}

func (s *capturingExecutionPayloadEnvelopeSigner) SignExecutionPayloadEnvelope(
	_ context.Context,
	_ e2wtypes.Account,
	_ phase0.Slot,
	envelope *gloas.ExecutionPayloadEnvelope,
) (phase0.BLSSignature, error) {
	s.calls++
	s.envelope = envelope
	if s.err != nil {
		return phase0.BLSSignature{}, s.err
	}
	return s.signature, nil
}

var _ signer.ExecutionPayloadEnvelopeSigner = (*capturingExecutionPayloadEnvelopeSigner)(nil)

type capturingExecutionPayloadEnvelopeSubmitter struct {
	opts *consensusapi.SubmitExecutionPayloadEnvelopeOpts
}

func (s *capturingExecutionPayloadEnvelopeSubmitter) SubmitExecutionPayloadEnvelope(
	_ context.Context,
	opts *consensusapi.SubmitExecutionPayloadEnvelopeOpts,
) error {
	s.opts = opts
	return nil
}

var _ submitter.ExecutionPayloadEnvelopeSubmitter = (*capturingExecutionPayloadEnvelopeSubmitter)(nil)

func (s *capturingBeaconBlockSigner) SignBeaconBlockProposal(
	_ context.Context,
	_ e2wtypes.Account,
	_ phase0.Slot,
	_ phase0.ValidatorIndex,
	_ phase0.Root,
	_ phase0.Root,
	_ phase0.Root,
) (phase0.BLSSignature, error) {
	s.calls++
	return s.signature, nil
}

type forkChainTime struct {
	gloasForkEpoch phase0.Epoch
}

func (*forkChainTime) GenesisTime() time.Time {
	return time.Time{}
}

func (*forkChainTime) StartOfSlot(phase0.Slot) time.Time {
	return time.Time{}
}

func (*forkChainTime) StartOfEpoch(phase0.Epoch) time.Time {
	return time.Time{}
}

func (*forkChainTime) CurrentSlot() phase0.Slot {
	return 0
}

func (*forkChainTime) CurrentEpoch() phase0.Epoch {
	return 0
}

func (*forkChainTime) SlotToEpoch(phase0.Slot) phase0.Epoch {
	return 0
}

func (*forkChainTime) FirstSlotOfEpoch(phase0.Epoch) phase0.Slot {
	return 0
}

func (s *forkChainTime) HardForkEpoch(context.Context, string) phase0.Epoch {
	return s.gloasForkEpoch
}

var _ chaintime.Service = (*forkChainTime)(nil)

type testAccount struct{}

func (*testAccount) ID() uuid.UUID {
	return uuid.Nil
}

func (*testAccount) Name() string {
	return "test"
}

func (*testAccount) PublicKey() e2types.PublicKey {
	return nil
}

var _ e2wtypes.Account = (*testAccount)(nil)
