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

package best_test

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1gloas "github.com/attestantio/go-eth2-client/api/v1/gloas"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/strategies/beaconblockproposal/best"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestEPBSProposal(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})

	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"one": &testEPBSProposalProvider{proposal: testGloasProposal(1, bellatrix.ExecutionAddress{0x01})},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot: phase0.Slot(1),
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.NotNil(t, response.Data)
}

func TestEPBSProposalReturnsIncludedCandidateAtSoftTimeout(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	includePayload := true
	candidate := &api.VersionedEPBSProposal{ExecutionPayloadIncluded: true}
	const timeout = 200 * time.Millisecond
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"included": &testEPBSProposalProvider{proposal: candidate},
			"error":    &testEPBSProposalProvider{err: errors.New("failed")},
			"slow":     &testEPBSProposalProvider{waitForCancellation: true},
		}),
		best.WithTimeout(timeout),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	started := time.Now()
	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{IncludePayload: &includePayload})
	elapsed := time.Since(started)
	require.NoError(t, err)
	require.Same(t, candidate, response.Data)
	require.Less(t, elapsed, 3*timeout/4)
}

func TestEPBSProposalPrefersIncludedCandidate(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	includePayload := true
	includedCandidate := &api.VersionedEPBSProposal{
		ExecutionPayloadIncluded: true,
		ConsensusValue:           big.NewInt(1),
	}
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"included": &testEPBSProposalProvider{proposal: includedCandidate},
			"external": &testEPBSProposalProvider{proposal: &api.VersionedEPBSProposal{
				ConsensusValue: big.NewInt(100),
			}},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{IncludePayload: &includePayload})
	require.NoError(t, err)
	require.Same(t, includedCandidate, response.Data)
}

func TestEPBSProposalRejectsZeroFeeRecipient(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	zeroFeeCandidate := testGloasProposal(100, bellatrix.ExecutionAddress{})
	validCandidate := testGloasProposal(1, bellatrix.ExecutionAddress{0x01})
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(2),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"zero-fee": &testEPBSProposalProvider{proposal: zeroFeeCandidate},
			"valid":    &testEPBSProposalProvider{proposal: validCandidate},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.NoError(t, err)
	require.Same(t, validCandidate, response.Data)
}

func TestEPBSProposalRejectsZeroFeeRecipientWithoutPayload(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	zeroFeeCandidate := testGloasProposalWithoutPayload(100, bellatrix.ExecutionAddress{})
	validCandidate := testGloasProposalWithoutPayload(1, bellatrix.ExecutionAddress{0x01})
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(2),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"zero-fee": &testEPBSProposalProvider{proposal: zeroFeeCandidate},
			"valid":    &testEPBSProposalProvider{proposal: validCandidate},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.NoError(t, err)
	require.Same(t, validCandidate, response.Data)
}

func TestEPBSProposalRejectsNilData(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	validCandidate := testGloasProposal(1, bellatrix.ExecutionAddress{0x01})
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(2),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"nil":   &testEPBSProposalProvider{},
			"valid": &testEPBSProposalProvider{proposal: validCandidate},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	includePayload := true
	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{IncludePayload: &includePayload})
	require.NoError(t, err)
	require.Same(t, validCandidate, response.Data)
}

func TestEPBSProposalRejectsMalformedIncludedGloasProposal(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	tests := []struct {
		name     string
		proposal *api.VersionedEPBSProposal
	}{
		{
			name: "MissingGloasContents",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
			},
		},
		{
			name: "MissingBlock",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
				GloasContents:            &apiv1gloas.BlockContents{},
			},
		},
		{
			name: "MissingBody",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
				GloasContents:            &apiv1gloas.BlockContents{Block: &gloas.BeaconBlock{}},
			},
		},
		{
			name: "MissingSignedExecutionPayloadBid",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
				GloasContents: &apiv1gloas.BlockContents{Block: &gloas.BeaconBlock{
					Body: &gloas.BeaconBlockBody{},
				}},
			},
		},
		{
			name: "MissingExecutionPayloadBidMessage",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
				GloasContents: &apiv1gloas.BlockContents{Block: &gloas.BeaconBlock{
					Body: &gloas.BeaconBlockBody{
						SignedExecutionPayloadBid: &gloas.SignedExecutionPayloadBid{},
					},
				}},
			},
		},
		{
			name: "CachedMissingBlock",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
			},
		},
		{
			name: "CachedMissingBody",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
				Gloas:   &gloas.BeaconBlock{},
			},
		},
		{
			name: "CachedMissingSignedExecutionPayloadBid",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
				Gloas: &gloas.BeaconBlock{
					Body: &gloas.BeaconBlockBody{},
				},
			},
		},
		{
			name: "CachedMissingExecutionPayloadBidMessage",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
				Gloas: &gloas.BeaconBlock{
					Body: &gloas.BeaconBlockBody{
						SignedExecutionPayloadBid: &gloas.SignedExecutionPayloadBid{},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validCandidate := testGloasProposal(1, bellatrix.ExecutionAddress{0x01})
			service, err := best.New(ctx,
				best.WithLogLevel(zerolog.Disabled),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithProcessConcurrency(2),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
					"malformed": &testEPBSProposalProvider{proposal: test.proposal},
					"valid":     &testEPBSProposalProvider{proposal: validCandidate},
				}),
				best.WithTimeout(time.Second),
				best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
			)
			require.NoError(t, err)

			response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
			require.NoError(t, err)
			require.Same(t, validCandidate, response.Data)
		})
	}
}

func testGloasProposal(value int64, feeRecipient bellatrix.ExecutionAddress) *api.VersionedEPBSProposal {
	return &api.VersionedEPBSProposal{
		Version:                  spec.DataVersionGloas,
		ExecutionPayloadIncluded: true,
		ConsensusValue:           big.NewInt(value),
		GloasContents: &apiv1gloas.BlockContents{
			Block: &gloas.BeaconBlock{
				Body: &gloas.BeaconBlockBody{
					SignedExecutionPayloadBid: &gloas.SignedExecutionPayloadBid{
						Message: &gloas.ExecutionPayloadBid{FeeRecipient: feeRecipient},
					},
				},
			},
		},
	}
}

func testGloasProposalWithoutPayload(value int64, feeRecipient bellatrix.ExecutionAddress) *api.VersionedEPBSProposal {
	proposal := testGloasProposal(value, feeRecipient)
	proposal.Gloas = proposal.GloasContents.Block
	proposal.GloasContents = nil
	proposal.ExecutionPayloadIncluded = false

	return proposal
}

func TestEPBSProposalExpandsClientGraffitiPerProvider(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	firstProvider := &clientGraffitiEPBSProposalProvider{
		client:   "first",
		graffiti: make(chan [32]byte, 1),
	}
	const longClient = "second-client-version-with-more-than-thirty-two-bytes"
	secondProvider := &clientGraffitiEPBSProposalProvider{
		client:   longClient,
		graffiti: make(chan [32]byte, 1),
	}
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(2),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"first":  firstProvider,
			"second": secondProvider,
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)
	var graffiti [32]byte
	copy(graffiti[:], "{{CLIENT}}")

	_, err = service.EPBSProposal(ctx, &api.EPBSProposalOpts{Graffiti: graffiti})
	require.NoError(t, err)
	var expectedFirst [32]byte
	copy(expectedFirst[:], "first")
	require.Equal(t, expectedFirst, <-firstProvider.graffiti)
	var expectedSecond [32]byte
	copy(expectedSecond[:], longClient)
	require.Equal(t, expectedSecond, <-secondProvider.graffiti)
}

func TestEPBSProposalPreservesGraffitiWhenClientLookupFails(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	provider := &clientGraffitiEPBSProposalProvider{
		nodeClientErr: errors.New("node client unavailable"),
		graffiti:      make(chan [32]byte, 1),
	}
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"provider": provider,
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	var graffiti [32]byte
	copy(graffiti[:], "configured {{CLIENT}}")
	_, err = service.EPBSProposal(ctx, &api.EPBSProposalOpts{Graffiti: graffiti})
	require.NoError(t, err)
	require.Equal(t, graffiti, <-provider.graffiti)
}

func TestEPBSProposalStartsProvidersWhileGraffitiClientLookupIsSlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	slowProvider := &slowClientGraffitiEPBSProposalProvider{
		nodeClientStarted: make(chan struct{}),
		release:           make(chan struct{}),
	}
	releaseSlowProvider := slowProvider.release
	t.Cleanup(func() {
		select {
		case <-releaseSlowProvider:
		default:
			close(releaseSlowProvider)
		}
	})
	healthyProvider := &waitingClientGraffitiEPBSProposalProvider{
		waitFor:         slowProvider.nodeClientStarted,
		proposalStarted: make(chan struct{}),
	}
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(2),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"slow":    slowProvider,
			"healthy": healthyProvider,
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)
	var graffiti [32]byte
	copy(graffiti[:], "{{CLIENT}}")

	errCh := make(chan error, 1)
	go func() {
		_, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Graffiti: graffiti})
		errCh <- err
	}()

	select {
	case <-slowProvider.nodeClientStarted:
	case <-time.After(200 * time.Millisecond):
		require.Fail(t, "slow provider client lookup did not start")
	}
	select {
	case <-healthyProvider.proposalStarted:
	case <-time.After(200 * time.Millisecond):
		require.Fail(t, "healthy provider proposal did not start promptly")
	}
	close(releaseSlowProvider)
	require.NoError(t, <-errCh)
}

type testEPBSProposalProvider struct {
	proposal            *api.VersionedEPBSProposal
	err                 error
	waitForCancellation bool
}

type clientGraffitiEPBSProposalProvider struct {
	client        string
	nodeClientErr error
	graffiti      chan [32]byte
}

func (*clientGraffitiEPBSProposalProvider) Proposal(
	_ context.Context,
	_ *api.ProposalOpts,
) (*api.Response[*api.VersionedProposal], error) {
	return nil, nil
}

func (p *clientGraffitiEPBSProposalProvider) EPBSProposal(
	_ context.Context,
	opts *api.EPBSProposalOpts,
) (*api.Response[*api.VersionedEPBSProposal], error) {
	p.graffiti <- opts.Graffiti
	return &api.Response[*api.VersionedEPBSProposal]{Data: &api.VersionedEPBSProposal{}}, nil
}

func (p *clientGraffitiEPBSProposalProvider) NodeClient(
	_ context.Context,
) (*api.Response[string], error) {
	if p.nodeClientErr != nil {
		return nil, p.nodeClientErr
	}
	return &api.Response[string]{Data: p.client}, nil
}

var _ eth2client.NodeClientProvider = (*clientGraffitiEPBSProposalProvider)(nil)

type slowClientGraffitiEPBSProposalProvider struct {
	nodeClientStarted chan struct{}
	release           chan struct{}
	startOnce         sync.Once
}

func (*slowClientGraffitiEPBSProposalProvider) Proposal(
	_ context.Context,
	_ *api.ProposalOpts,
) (*api.Response[*api.VersionedProposal], error) {
	return nil, nil
}

func (*slowClientGraffitiEPBSProposalProvider) EPBSProposal(
	_ context.Context,
	_ *api.EPBSProposalOpts,
) (*api.Response[*api.VersionedEPBSProposal], error) {
	return &api.Response[*api.VersionedEPBSProposal]{Data: &api.VersionedEPBSProposal{}}, nil
}

func (p *slowClientGraffitiEPBSProposalProvider) NodeClient(
	ctx context.Context,
) (*api.Response[string], error) {
	p.startOnce.Do(func() {
		close(p.nodeClientStarted)
	})
	select {
	case <-p.release:
		return &api.Response[string]{Data: "slow"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var _ eth2client.NodeClientProvider = (*slowClientGraffitiEPBSProposalProvider)(nil)

type waitingClientGraffitiEPBSProposalProvider struct {
	waitFor         <-chan struct{}
	proposalStarted chan struct{}
	proposalOnce    sync.Once
}

func (*waitingClientGraffitiEPBSProposalProvider) Proposal(
	_ context.Context,
	_ *api.ProposalOpts,
) (*api.Response[*api.VersionedProposal], error) {
	return nil, nil
}

func (p *waitingClientGraffitiEPBSProposalProvider) EPBSProposal(
	_ context.Context,
	_ *api.EPBSProposalOpts,
) (*api.Response[*api.VersionedEPBSProposal], error) {
	p.proposalOnce.Do(func() {
		close(p.proposalStarted)
	})
	return &api.Response[*api.VersionedEPBSProposal]{Data: &api.VersionedEPBSProposal{}}, nil
}

func (p *waitingClientGraffitiEPBSProposalProvider) NodeClient(
	ctx context.Context,
) (*api.Response[string], error) {
	select {
	case <-p.waitFor:
		return &api.Response[string]{Data: "healthy"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var _ eth2client.NodeClientProvider = (*waitingClientGraffitiEPBSProposalProvider)(nil)

func (p *testEPBSProposalProvider) Proposal(_ context.Context, _ *api.ProposalOpts) (*api.Response[*api.VersionedProposal], error) {
	return nil, nil
}

func (p *testEPBSProposalProvider) EPBSProposal(ctx context.Context,
	_ *api.EPBSProposalOpts,
) (
	*api.Response[*api.VersionedEPBSProposal],
	error,
) {
	if p.waitForCancellation {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if p.err != nil {
		return nil, p.err
	}

	return &api.Response[*api.VersionedEPBSProposal]{Data: p.proposal}, nil
}
