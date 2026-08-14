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
	"math"
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
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	prometheusmetrics "github.com/attestantio/vouch/services/metrics/prometheus"
	"github.com/attestantio/vouch/services/signer"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// skipcq: GO-R1005
func TestProposeGloas(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name                       string
		executionPayloadIncluded   bool
		blockAuctioneer            bool
		builderBoostFactor         uint64
		proposerIndexMismatch      bool
		builderIndexMismatch       bool
		foreignBuilderIndex        bool
		envelopeRootMismatch       bool
		envelopePayloadMissing     bool
		executionPayloadBidMissing bool
		envelopeSignerErr          error
		envelopeSubmitterErr       error
		forkEpochAtConstruction    phase0.Epoch
		forkEpochAtUse             phase0.Epoch
		updateForkEpochAtUse       bool
		err                        string
	}{
		{
			name:                     "PayloadIncluded",
			executionPayloadIncluded: true,
			builderBoostFactor:       100,
		},
		{
			name:                     "ForkEpochAvailableAfterConstruction",
			executionPayloadIncluded: true,
			forkEpochAtConstruction:  phase0.Epoch(^uint64(0)),
			forkEpochAtUse:           0,
			updateForkEpochAtUse:     true,
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
			name:                     "MismatchedEnvelopeBuilderIndex",
			executionPayloadIncluded: true,
			builderIndexMismatch:     true,
			err:                      "failed to propose block: ePBS execution payload envelope is for incorrect builder index",
		},
		{
			name:                     "ForeignBuilderIndex",
			executionPayloadIncluded: true,
			foreignBuilderIndex:      true,
			err:                      "failed to propose block: ePBS execution payload bid is not self-built",
		},
		{
			name:                     "MissingEnvelopePayload",
			executionPayloadIncluded: true,
			envelopePayloadMissing:   true,
			err:                      "failed to propose block: ePBS execution payload envelope has no payload",
		},
		{
			name:                       "MissingExecutionPayloadBid",
			executionPayloadIncluded:   true,
			executionPayloadBidMissing: true,
			err:                        "failed to propose block: ePBS proposal has no execution payload bid",
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
		{
			name:                     "EnvelopeSubmissionFailure",
			executionPayloadIncluded: true,
			envelopeSubmitterErr:     errors.New("envelope submission failed"),
			err:                      "failed to propose block: failed to submit execution payload envelope after block publication: envelope submission failed",
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
					setSelfBuildBuilderIndex(t, response.Data)
					blockRoot, err := response.Data.GloasContents.Block.HashTreeRoot()
					require.NoError(t, err)
					response.Data.GloasContents.ExecutionPayloadEnvelope.BeaconBlockRoot = blockRoot
					if test.envelopeRootMismatch {
						response.Data.GloasContents.ExecutionPayloadEnvelope.BeaconBlockRoot[0] ^= 0xff
					}
					if test.builderIndexMismatch {
						response.Data.GloasContents.ExecutionPayloadEnvelope.BuilderIndex++
					}
					if test.foreignBuilderIndex {
						response.Data.GloasContents.Block.Body.SignedExecutionPayloadBid.Message.BuilderIndex++
						response.Data.GloasContents.ExecutionPayloadEnvelope.BuilderIndex = response.Data.GloasContents.Block.Body.SignedExecutionPayloadBid.Message.BuilderIndex
					}
					if test.envelopePayloadMissing {
						response.Data.GloasContents.ExecutionPayloadEnvelope.Payload = nil
					}
					if test.executionPayloadBidMissing {
						response.Data.GloasContents.Block.Body.SignedExecutionPayloadBid = nil
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
			envelopeSubmitter := &capturingExecutionPayloadEnvelopeSubmitter{err: test.envelopeSubmitterErr}

			chainTime := &forkChainTime{gloasForkEpoch: test.forkEpochAtConstruction}
			var monitor metrics.Service = nullmetrics.New()

			params := []standard.Parameter{
				standard.WithLogLevel(zerolog.TraceLevel),
				standard.WithMonitor(monitor),
				standard.WithProposalDataProvider(proposalClient),
				standard.WithChainTime(chainTime),
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
			if test.updateForkEpochAtUse {
				chainTime.gloasForkEpoch = test.forkEpochAtUse
			}

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
				if test.envelopeSubmitterErr == nil {
					require.Nil(t, proposalSubmitter.proposal)
					require.Zero(t, proposalSubmitter.calls)
				} else {
					require.NotNil(t, proposalSubmitter.proposal)
					require.Equal(t, 1, proposalSubmitter.calls)
					require.Equal(t, 3, envelopeSubmitter.calls)
				}
				if test.envelopeRootMismatch || test.builderIndexMismatch || test.foreignBuilderIndex || test.envelopePayloadMissing || test.executionPayloadBidMissing {
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
				directBlockRoot, err := responseProposal.GloasContents.Block.HashTreeRoot()
				require.NoError(t, err)
				bodyRoot, err := responseProposal.GloasContents.Block.Body.HashTreeRoot()
				require.NoError(t, err)
				headerRoot, err := (&phase0.BeaconBlockHeader{
					Slot:          responseProposal.GloasContents.Block.Slot,
					ProposerIndex: responseProposal.GloasContents.Block.ProposerIndex,
					ParentRoot:    responseProposal.GloasContents.Block.ParentRoot,
					StateRoot:     responseProposal.GloasContents.Block.StateRoot,
					BodyRoot:      bodyRoot,
				}).HashTreeRoot()
				require.NoError(t, err)
				require.Equal(t, directBlockRoot, headerRoot)
				require.Equal(t, phase0.Root(bodyRoot), blockSigner.bodyRoot)
			}
		})
	}
}

func TestProposeGloasProposalSource(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name                     string
		executionPayloadIncluded bool
		source                   string
		expectedCountDelta       float64
		err                      string
	}{
		{
			name:                     "SelfBuiltPayload",
			executionPayloadIncluded: true,
			source:                   "local",
			expectedCountDelta:       1,
		},
		{
			name:                     "ProtocolBuilderPayload",
			executionPayloadIncluded: false,
			source:                   "builder",
			expectedCountDelta:       0,
			err:                      "failed to propose block: ePBS proposal excludes requested execution payload",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			monitor, err := prometheusmetrics.New(ctx,
				prometheusmetrics.WithLogLevel(zerolog.Disabled),
				prometheusmetrics.WithAddress("localhost:0"),
			)
			require.NoError(t, err)
			proposalSourceCountBefore := beaconBlockProposalSourceCount(t, test.source)
			service, duty, blockSigner, envelopeSigner, envelopeSubmitter, _ := newGloasProposerForProposalSource(ctx, t, test.executionPayloadIncluded, monitor)

			err = service.Propose(ctx, duty)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, proposalSourceCountBefore+test.expectedCountDelta, beaconBlockProposalSourceCount(t, test.source))
			if !test.executionPayloadIncluded {
				require.Zero(t, blockSigner.calls)
				require.Zero(t, envelopeSigner.calls)
				require.Nil(t, envelopeSubmitter.opts)
			}
		})
	}
}

func TestProposeGloasProposalSourceSubmissionFailure(t *testing.T) {
	ctx := context.Background()

	monitor, err := prometheusmetrics.New(ctx,
		prometheusmetrics.WithLogLevel(zerolog.Disabled),
		prometheusmetrics.WithAddress("localhost:0"),
	)
	require.NoError(t, err)
	proposalSourceCountBefore := beaconBlockProposalSourceCount(t, "local")
	service, duty, _, _, envelopeSubmitter, proposalSubmitter := newGloasProposerForProposalSource(ctx, t, true, monitor)
	proposalSubmitter.err = errors.New("submit failed")

	err = service.Propose(ctx, duty)
	require.EqualError(t, err, "failed to propose block: failed to submit proposal: submit failed")
	require.Equal(t, proposalSourceCountBefore, beaconBlockProposalSourceCount(t, "local"))
	require.Nil(t, envelopeSubmitter.opts)
}

func setSelfBuildBuilderIndex(t *testing.T, proposal *consensusapi.VersionedEPBSProposal) {
	t.Helper()

	proposal.GloasContents.Block.Body.SignedExecutionPayloadBid.Message.BuilderIndex = gloas.BuilderIndex(math.MaxUint64)
	proposal.GloasContents.ExecutionPayloadEnvelope.BuilderIndex = gloas.BuilderIndex(math.MaxUint64)
	bodyRoot, err := proposal.GloasContents.Block.Body.HashTreeRoot()
	require.NoError(t, err)
	convertedBodyRoot := phase0.Root(bodyRoot)
	proposal.BeaconBlockBodyRoot = &convertedBodyRoot
}

func newGloasProposerForProposalSource(
	ctx context.Context,
	t *testing.T,
	executionPayloadIncluded bool,
	monitor metrics.Service,
) (*standard.Service,
	*beaconblockproposer.Duty,
	*capturingBeaconBlockSigner,
	*capturingExecutionPayloadEnvelopeSigner,
	*capturingExecutionPayloadEnvelopeSubmitter,
	*capturingProposalSubmitter,
) {
	t.Helper()

	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	responseClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	proposalClient.EPBSProposalFunc = func(ctx context.Context, opts *consensusapi.EPBSProposalOpts) (*consensusapi.Response[*consensusapi.VersionedEPBSProposal], error) {
		responseOpts := *opts
		responseOpts.IncludePayload = &executionPayloadIncluded
		response, err := responseClient.EPBSProposal(ctx, &responseOpts)
		require.NoError(t, err)
		if response.Data.ExecutionPayloadIncluded {
			response.Data.GloasContents.KZGProofs = []deneb.KZGProof{{0x04}}
			response.Data.GloasContents.Blobs = []deneb.Blob{{0x05}}
			setSelfBuildBuilderIndex(t, response.Data)
			blockRoot, err := response.Data.GloasContents.Block.HashTreeRoot()
			require.NoError(t, err)
			response.Data.GloasContents.ExecutionPayloadEnvelope.BeaconBlockRoot = blockRoot
		}

		return response, nil
	}

	proposalSubmitter := &capturingProposalSubmitter{}
	signer := mocksigner.New()
	blockSigner := &capturingBeaconBlockSigner{signature: phase0.BLSSignature{0x01}}
	envelopeSigner := &capturingExecutionPayloadEnvelopeSigner{signature: phase0.BLSSignature{0x03}}
	envelopeSubmitter := &capturingExecutionPayloadEnvelopeSubmitter{}
	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(monitor),
		standard.WithProposalDataProvider(proposalClient),
		standard.WithChainTime(&forkChainTime{gloasForkEpoch: 0}),
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

	return service, duty, blockSigner, envelopeSigner, envelopeSubmitter, proposalSubmitter
}

func beaconBlockProposalSourceCount(t *testing.T, source string) float64 {
	t.Helper()

	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, metricFamily := range metricFamilies {
		if metricFamily.GetName() != "vouch_beaconblockproposal_process_blocks_total" {
			continue
		}
		for _, metric := range metricFamily.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "method" && label.GetValue() == source {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}

	return 0
}

// TestProposeGloasSignsRetainedBodyRoot proves that Propose signs and submits the
// body root retained on the proposal (BeaconBlockBodyRoot), not the body root the
// generated Body.HashTreeRoot() would compute.  On a custom preset those two roots
// differ, because the generated hasher inlines mainnet sizes; the mainnet fixtures
// used elsewhere in this file have the two coincide, so they cannot tell a correct
// implementation from one that silently falls back to the wrong root.  This test
// makes them deliberately differ.
func TestProposeGloasSignsRetainedBodyRoot(t *testing.T) {
	ctx := context.Background()

	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	responseClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)

	var generatedBodyRoot, retainedBodyRoot phase0.Root
	proposalClient.EPBSProposalFunc = func(ctx context.Context, opts *consensusapi.EPBSProposalOpts) (*consensusapi.Response[*consensusapi.VersionedEPBSProposal], error) {
		includePayload := true
		responseOpts := *opts
		responseOpts.IncludePayload = &includePayload
		response, err := responseClient.EPBSProposal(ctx, &responseOpts)
		if err != nil {
			return nil, err
		}
		response.Data.GloasContents.KZGProofs = []deneb.KZGProof{{0x04}}
		response.Data.GloasContents.Blobs = []deneb.Blob{{0x05}}
		setSelfBuildBuilderIndex(t, response.Data)

		block := response.Data.GloasContents.Block
		generatedRoot, err := block.Body.HashTreeRoot()
		require.NoError(t, err)
		generatedBodyRoot = generatedRoot

		// Simulate a minimal-preset node: the transport's spec-aware retained
		// root deliberately differs from what the generated hasher computes.
		retainedBodyRoot = generatedBodyRoot
		retainedBodyRoot[0] ^= 0xff
		response.Data.BeaconBlockBodyRoot = &retainedBodyRoot

		blockRoot, err := (&phase0.BeaconBlockHeader{
			Slot:          block.Slot,
			ProposerIndex: block.ProposerIndex,
			ParentRoot:    block.ParentRoot,
			StateRoot:     block.StateRoot,
			BodyRoot:      retainedBodyRoot,
		}).HashTreeRoot()
		require.NoError(t, err)
		response.Data.GloasContents.ExecutionPayloadEnvelope.BeaconBlockRoot = blockRoot

		return response, nil
	}

	proposalSubmitter := &capturingProposalSubmitter{}
	signer := mocksigner.New()
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

	require.NoError(t, service.Propose(ctx, duty))

	require.Equal(t, retainedBodyRoot, blockSigner.bodyRoot)
	require.NotEqual(t, generatedBodyRoot, blockSigner.bodyRoot)

	require.NotNil(t, proposalSubmitter.proposal)
	require.NotNil(t, proposalSubmitter.proposal.Gloas)
	require.NotNil(t, proposalSubmitter.proposal.Gloas.Message)
	require.Equal(t, duty.Slot(), proposalSubmitter.proposal.Gloas.Message.Slot)
	require.NotNil(t, envelopeSubmitter.opts)
	require.NotNil(t, envelopeSubmitter.opts.SignedExecutionPayloadEnvelope)
	require.NotNil(t, envelopeSubmitter.opts.SignedExecutionPayloadEnvelope.Gloas)
}

// TestProposeGloasMissingBodyRootFails proves that a proposal missing its
// retained body root -- as a provider that never set BeaconBlockBodyRoot would
// produce -- fails the duty outright rather than falling back to the generated,
// potentially-wrong Body.HashTreeRoot().  Nothing may be signed or submitted:
// signing over the wrong root would be worse than not proposing at all.
func TestProposeGloasMissingBodyRootFails(t *testing.T) {
	ctx := context.Background()

	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	responseClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	proposalClient.EPBSProposalFunc = func(ctx context.Context, opts *consensusapi.EPBSProposalOpts) (*consensusapi.Response[*consensusapi.VersionedEPBSProposal], error) {
		includePayload := true
		responseOpts := *opts
		responseOpts.IncludePayload = &includePayload
		response, err := responseClient.EPBSProposal(ctx, &responseOpts)
		if err != nil {
			return nil, err
		}
		response.Data.GloasContents.KZGProofs = []deneb.KZGProof{{0x04}}
		response.Data.GloasContents.Blobs = []deneb.Blob{{0x05}}
		setSelfBuildBuilderIndex(t, response.Data)
		blockRoot, err := response.Data.GloasContents.Block.HashTreeRoot()
		require.NoError(t, err)
		response.Data.GloasContents.ExecutionPayloadEnvelope.BeaconBlockRoot = blockRoot
		// Simulate a provider that never populated the retained root.
		response.Data.BeaconBlockBodyRoot = nil

		return response, nil
	}

	proposalSubmitter := &capturingProposalSubmitter{}
	signer := mocksigner.New()
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

	err = service.Propose(ctx, duty)
	require.EqualError(t, err, "failed to propose block: failed to calculate hash tree root of ePBS block body: no beacon block body root")
	require.Zero(t, blockSigner.calls)
	require.Zero(t, envelopeSigner.calls)
	require.Nil(t, proposalSubmitter.proposal)
	require.Zero(t, proposalSubmitter.calls)
	require.Nil(t, envelopeSubmitter.opts)
}

func TestProposeGloasStartsBothSignaturesBeforePublication(t *testing.T) {
	ctx := context.Background()
	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	responseClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	proposalClient.EPBSProposalFunc = func(ctx context.Context, opts *consensusapi.EPBSProposalOpts) (*consensusapi.Response[*consensusapi.VersionedEPBSProposal], error) {
		includePayload := true
		responseOpts := *opts
		responseOpts.IncludePayload = &includePayload
		response, err := responseClient.EPBSProposal(ctx, &responseOpts)
		if err != nil {
			return nil, err
		}
		response.Data.GloasContents.KZGProofs = []deneb.KZGProof{{0x04}}
		response.Data.GloasContents.Blobs = []deneb.Blob{{0x05}}
		setSelfBuildBuilderIndex(t, response.Data)
		blockRoot, err := response.Data.GloasContents.Block.HashTreeRoot()
		require.NoError(t, err)
		response.Data.GloasContents.ExecutionPayloadEnvelope.BeaconBlockRoot = blockRoot

		return response, nil
	}

	blockSigningStarted := make(chan struct{}, 1)
	envelopeSigningStarted := make(chan struct{}, 1)
	releaseSignatures := make(chan struct{})
	defer func() {
		select {
		case <-releaseSignatures:
		default:
			close(releaseSignatures)
		}
	}()
	proposalSubmitter := &capturingProposalSubmitter{}
	envelopeSubmitter := &capturingExecutionPayloadEnvelopeSubmitter{}
	blockSigner := &capturingBeaconBlockSigner{
		signature: phase0.BLSSignature{0x01},
		started:   blockSigningStarted,
		release:   releaseSignatures,
	}
	envelopeSigner := &capturingExecutionPayloadEnvelopeSigner{
		signature: phase0.BLSSignature{0x03},
		started:   envelopeSigningStarted,
		release:   releaseSignatures,
	}
	signer := mocksigner.New()
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
	result := make(chan error, 1)
	go func() {
		result <- service.Propose(ctx, duty)
	}()

	select {
	case <-blockSigningStarted:
	case <-time.After(time.Second):
		t.Fatal("block signing did not start")
	}
	select {
	case <-envelopeSigningStarted:
	case <-time.After(time.Second):
		t.Fatal("execution payload envelope signing did not start")
	}
	require.Nil(t, proposalSubmitter.proposal)
	require.Nil(t, envelopeSubmitter.opts)

	close(releaseSignatures)
	require.NoError(t, <-result)
	require.NotNil(t, proposalSubmitter.proposal)
	require.NotNil(t, envelopeSubmitter.opts)
}

func TestProposeGloasCancelsPeerSigningAfterFailure(t *testing.T) {
	ctx := context.Background()
	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	responseClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	proposalClient.EPBSProposalFunc = func(ctx context.Context, opts *consensusapi.EPBSProposalOpts) (*consensusapi.Response[*consensusapi.VersionedEPBSProposal], error) {
		includePayload := true
		responseOpts := *opts
		responseOpts.IncludePayload = &includePayload
		response, err := responseClient.EPBSProposal(ctx, &responseOpts)
		if err != nil {
			return nil, err
		}
		response.Data.GloasContents.KZGProofs = []deneb.KZGProof{{0x04}}
		response.Data.GloasContents.Blobs = []deneb.Blob{{0x05}}
		setSelfBuildBuilderIndex(t, response.Data)
		blockRoot, err := response.Data.GloasContents.Block.HashTreeRoot()
		require.NoError(t, err)
		response.Data.GloasContents.ExecutionPayloadEnvelope.BeaconBlockRoot = blockRoot

		return response, nil
	}

	blockSigningStarted := make(chan struct{}, 1)
	envelopeSigningStarted := make(chan struct{}, 1)
	envelopeSigningCancelled := make(chan struct{}, 1)
	releaseBlockSigning := make(chan struct{})
	proposalSubmitter := &capturingProposalSubmitter{}
	envelopeSubmitter := &capturingExecutionPayloadEnvelopeSubmitter{}
	blockSigner := &capturingBeaconBlockSigner{
		err:     errors.New("block signing failed"),
		started: blockSigningStarted,
		release: releaseBlockSigning,
	}
	envelopeSigner := &contextBlockingExecutionPayloadEnvelopeSigner{
		started:   envelopeSigningStarted,
		cancelled: envelopeSigningCancelled,
	}
	signer := mocksigner.New()
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
	result := make(chan error, 1)
	go func() {
		result <- service.Propose(ctx, duty)
	}()

	select {
	case <-blockSigningStarted:
	case <-time.After(time.Second):
		t.Fatal("block signing did not start")
	}
	select {
	case <-envelopeSigningStarted:
	case <-time.After(time.Second):
		t.Fatal("execution payload envelope signing did not start")
	}
	close(releaseBlockSigning)

	select {
	case err := <-result:
		require.EqualError(t, err, "failed to propose block: failed to sign ePBS beacon block proposal: block signing failed")
	case <-time.After(time.Second):
		t.Fatal("proposal did not return after block signing failure")
	}
	select {
	case <-envelopeSigningCancelled:
	case <-time.After(time.Second):
		t.Fatal("execution payload envelope signing was not cancelled")
	}
	require.Nil(t, proposalSubmitter.proposal)
	require.Nil(t, envelopeSubmitter.opts)
}

func TestProposeGloasCancelsBlockedBlockSigningAfterEnvelopeFailure(t *testing.T) {
	ctx := context.Background()
	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	responseClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	proposalClient.EPBSProposalFunc = func(ctx context.Context, opts *consensusapi.EPBSProposalOpts) (*consensusapi.Response[*consensusapi.VersionedEPBSProposal], error) {
		includePayload := true
		responseOpts := *opts
		responseOpts.IncludePayload = &includePayload
		response, err := responseClient.EPBSProposal(ctx, &responseOpts)
		if err != nil {
			return nil, err
		}
		response.Data.GloasContents.KZGProofs = []deneb.KZGProof{{0x04}}
		response.Data.GloasContents.Blobs = []deneb.Blob{{0x05}}
		setSelfBuildBuilderIndex(t, response.Data)
		blockRoot, err := response.Data.GloasContents.Block.HashTreeRoot()
		require.NoError(t, err)
		response.Data.GloasContents.ExecutionPayloadEnvelope.BeaconBlockRoot = blockRoot

		return response, nil
	}

	blockSigningStarted := make(chan struct{}, 1)
	blockSigningCancelled := make(chan struct{}, 1)
	envelopeSigningStarted := make(chan struct{}, 1)
	proposalSubmitter := &capturingProposalSubmitter{}
	envelopeSubmitter := &capturingExecutionPayloadEnvelopeSubmitter{}
	signingErr := errors.New("signing failed")
	blockSigner := &contextBlockingBeaconBlockSigner{
		started:   blockSigningStarted,
		cancelled: blockSigningCancelled,
		err:       signingErr,
	}
	envelopeSigner := &capturingExecutionPayloadEnvelopeSigner{
		err:     signingErr,
		started: envelopeSigningStarted,
	}
	signer := mocksigner.New()
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
	result := make(chan error, 1)
	go func() {
		result <- service.Propose(ctx, duty)
	}()

	select {
	case <-blockSigningStarted:
	case <-time.After(time.Second):
		t.Fatal("block signing did not start")
	}
	select {
	case <-envelopeSigningStarted:
	case <-time.After(time.Second):
		t.Fatal("execution payload envelope signing did not start")
	}
	select {
	case err := <-result:
		require.EqualError(t, err, "failed to propose block: failed to sign execution payload envelope: signing failed")
	case <-time.After(time.Second):
		t.Fatal("proposal did not return after execution payload envelope signing failure")
	}
	select {
	case <-blockSigningCancelled:
	case <-time.After(time.Second):
		t.Fatal("block signing was not cancelled")
	}
	require.Nil(t, proposalSubmitter.proposal)
	require.Nil(t, envelopeSubmitter.opts)
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
		standard.WithExecutionPayloadEnvelopeSubmitter(responseClient),
		standard.WithRANDAORevealSigner(signer),
		standard.WithBeaconBlockSigner(blockSigner),
		standard.WithExecutionPayloadEnvelopeSigner(signer),
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
	err      error
}

func (s *capturingProposalSubmitter) SubmitProposal(_ context.Context, proposal *consensusapi.VersionedSignedProposal) error {
	s.calls++
	s.proposal = proposal

	return s.err
}

var _ submitter.ProposalSubmitter = (*capturingProposalSubmitter)(nil)

type capturingBeaconBlockSigner struct {
	signature phase0.BLSSignature
	bodyRoot  phase0.Root
	calls     int
	err       error
	started   chan<- struct{}
	release   <-chan struct{}
}

type capturingExecutionPayloadEnvelopeSigner struct {
	signature phase0.BLSSignature
	envelope  *gloas.ExecutionPayloadEnvelope
	calls     int
	err       error
	started   chan<- struct{}
	release   <-chan struct{}
}

func (s *capturingExecutionPayloadEnvelopeSigner) SignExecutionPayloadEnvelope(
	_ context.Context,
	_ e2wtypes.Account,
	_ phase0.Slot,
	envelope *gloas.ExecutionPayloadEnvelope,
) (phase0.BLSSignature, error) {
	s.calls++
	s.envelope = envelope
	if s.started != nil {
		s.started <- struct{}{}
	}
	if s.release != nil {
		<-s.release
	}
	if s.err != nil {
		return phase0.BLSSignature{}, s.err
	}
	return s.signature, nil
}

var _ signer.ExecutionPayloadEnvelopeSigner = (*capturingExecutionPayloadEnvelopeSigner)(nil)

type contextBlockingExecutionPayloadEnvelopeSigner struct {
	started   chan<- struct{}
	cancelled chan<- struct{}
}

func (s *contextBlockingExecutionPayloadEnvelopeSigner) SignExecutionPayloadEnvelope(
	ctx context.Context,
	_ e2wtypes.Account,
	_ phase0.Slot,
	_ *gloas.ExecutionPayloadEnvelope,
) (phase0.BLSSignature, error) {
	s.started <- struct{}{}
	<-ctx.Done()
	s.cancelled <- struct{}{}

	return phase0.BLSSignature{}, ctx.Err()
}

var _ signer.ExecutionPayloadEnvelopeSigner = (*contextBlockingExecutionPayloadEnvelopeSigner)(nil)

type contextBlockingBeaconBlockSigner struct {
	started   chan<- struct{}
	cancelled chan<- struct{}
	err       error
}

func (s *contextBlockingBeaconBlockSigner) SignBeaconBlockProposal(
	ctx context.Context,
	_ e2wtypes.Account,
	_ phase0.Slot,
	_ phase0.ValidatorIndex,
	_ phase0.Root,
	_ phase0.Root,
	_ phase0.Root,
) (phase0.BLSSignature, error) {
	s.started <- struct{}{}
	<-ctx.Done()
	s.cancelled <- struct{}{}

	if s.err != nil {
		return phase0.BLSSignature{}, s.err
	}

	return phase0.BLSSignature{}, ctx.Err()
}

var _ signer.BeaconBlockSigner = (*contextBlockingBeaconBlockSigner)(nil)

type capturingExecutionPayloadEnvelopeSubmitter struct {
	opts  *consensusapi.SubmitExecutionPayloadEnvelopeOpts
	calls int
	err   error
}

func (s *capturingExecutionPayloadEnvelopeSubmitter) SubmitExecutionPayloadEnvelope(
	_ context.Context,
	opts *consensusapi.SubmitExecutionPayloadEnvelopeOpts,
) error {
	s.calls++
	s.opts = opts

	return s.err
}

var _ submitter.ExecutionPayloadEnvelopeSubmitter = (*capturingExecutionPayloadEnvelopeSubmitter)(nil)

func (s *capturingBeaconBlockSigner) SignBeaconBlockProposal(
	_ context.Context,
	_ e2wtypes.Account,
	_ phase0.Slot,
	_ phase0.ValidatorIndex,
	_ phase0.Root,
	_ phase0.Root,
	bodyRoot phase0.Root,
) (phase0.BLSSignature, error) {
	s.calls++
	s.bodyRoot = bodyRoot
	if s.started != nil {
		s.started <- struct{}{}
	}
	if s.release != nil {
		<-s.release
	}
	if s.err != nil {
		return phase0.BLSSignature{}, s.err
	}
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
