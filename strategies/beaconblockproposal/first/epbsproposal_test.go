// Copyright © 2020 - 2026 Attestant Limited.
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

package first_test

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	apiv1gloas "github.com/attestantio/go-eth2-client/api/v1/gloas"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/strategies/beaconblockproposal/first"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestEPBSProposalAcceptsUnknownValue(t *testing.T) {
	ctx := context.Background()

	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"one": &epbsProposalProvider{proposal: gloasEPBSProposal(bellatrix.ExecutionAddress{0x01})},
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot: phase0.Slot(1),
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.NotNil(t, response.Data)
	require.Nil(t, response.Data.ExecutionValue)
}

func TestEPBSProposalDoesNotLeaveLateProvidersBlocked(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"fast":  &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}},
			"late1": &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}, release: release},
			"late2": &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}, release: release},
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.NoError(t, err)
	require.NotNil(t, response)
	close(release)

	require.Eventually(t, func() bool {
		stack := make([]byte, 64*1024)
		stackLength := runtime.Stack(stack, true)
		return !strings.Contains(string(stack[:stackLength]), "strategies/beaconblockproposal/first.(*Service).EPBSProposal.func1")
	}, time.Second, 10*time.Millisecond)
}

func TestEPBSProposalSkipsBuilderBidFromUnreadyProvider(t *testing.T) {
	ctx := context.Background()
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"unready": &epbsProposalProvider{proposal: gloasEPBSProposalWithoutPayload(bellatrix.ExecutionAddress{0x01})},
		}),
		first.WithProviderReadiness(&providerReadiness{ready: false}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
}

func TestEPBSProposalAcceptsSelfBuiltProposalFromUnreadyProvider(t *testing.T) {
	ctx := context.Background()
	proposal := gloasEPBSProposal(bellatrix.ExecutionAddress{0x01})
	proposal.GloasContents.Block.Body.SignedExecutionPayloadBid.Message.BuilderIndex = gloas.BuilderIndex(^uint64(0))
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"unready": &epbsProposalProvider{proposal: proposal},
		}),
		first.WithProviderReadiness(&providerReadiness{ready: false}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1})
	require.NoError(t, err)
	require.Same(t, proposal, response.Data)
}

func TestEPBSProposalSkipsProposalWithoutRequestedPayload(t *testing.T) {
	ctx := context.Background()
	includePayload := true
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"excluded": &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}},
		}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{IncludePayload: &includePayload})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
}

func TestEPBSProposalSkipsZeroFeeRecipient(t *testing.T) {
	ctx := context.Background()
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"zero-fee": &epbsProposalProvider{proposal: gloasEPBSProposal(bellatrix.ExecutionAddress{})},
		}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
}

func TestEPBSProposalSkipsNilResponse(t *testing.T) {
	ctx := context.Background()
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"nil": &epbsProposalProvider{nilResponse: true},
		}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
}

func TestEPBSProposalSkipsMalformedGloasProposal(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		proposal *api.VersionedEPBSProposal
	}{
		{
			name: "Nil",
		},
		{
			name: "GloasWithoutBlock",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
			},
		},
		{
			name: "GloasContentsWithoutBlock",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
				GloasContents:            &apiv1gloas.BlockContents{},
			},
		},
		{
			name: "GloasContentsNil",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
			},
		},
		{
			name: "BlockWithoutBody",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
				Gloas:   &gloas.BeaconBlock{},
			},
		},
		{
			name: "BodyWithoutBid",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
				Gloas: &gloas.BeaconBlock{
					Body: &gloas.BeaconBlockBody{},
				},
			},
		},
		{
			name: "BidWithoutMessage",
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
			service, err := first.New(ctx,
				first.WithLogLevel(zerolog.Disabled),
				first.WithClientMonitor(nullmetrics.New()),
				first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
					"malformed": &epbsProposalProvider{proposal: test.proposal},
				}),
				first.WithTimeout(10*time.Millisecond),
			)
			require.NoError(t, err)

			response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
			require.Nil(t, response)
			require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
		})
	}
}

func TestEPBSProposalWaitsForProposalWithRequestedPayload(t *testing.T) {
	ctx := context.Background()
	includePayload := true
	release := make(chan struct{})
	included := &api.VersionedEPBSProposal{ExecutionPayloadIncluded: true}
	time.AfterFunc(20*time.Millisecond, func() {
		close(release)
	})
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"excluded": &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}},
			"included": &epbsProposalProvider{proposal: included, release: release},
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{IncludePayload: &includePayload})
	require.NoError(t, err)
	require.Same(t, included, response.Data)
}

// gloasEPBSProposal returns a self-built proposal: it carries the payload, which only the
// beacon node's own build can do.
func gloasEPBSProposal(feeRecipient bellatrix.ExecutionAddress) *api.VersionedEPBSProposal {
	return &api.VersionedEPBSProposal{
		Version:                  spec.DataVersionGloas,
		ExecutionPayloadIncluded: true,
		GloasContents: &apiv1gloas.BlockContents{
			Block: &gloas.BeaconBlock{
				Body: &gloas.BeaconBlockBody{
					SignedExecutionPayloadBid: &gloas.SignedExecutionPayloadBid{
						Message: &gloas.ExecutionPayloadBid{
							BuilderIndex: gloas.BuilderIndex(^uint64(0)),
							FeeRecipient: feeRecipient,
						},
					},
				},
			},
		},
	}
}

type providerReadiness struct {
	ready bool
}

func (p *providerReadiness) ProviderReady(string, phase0.Slot, phase0.ValidatorIndex) bool {
	return p.ready
}

type epbsProposalProvider struct {
	proposal    *api.VersionedEPBSProposal
	opts        *api.EPBSProposalOpts
	release     <-chan struct{}
	nilResponse bool
}

func (*epbsProposalProvider) Proposal(_ context.Context, _ *api.ProposalOpts) (*api.Response[*api.VersionedProposal], error) {
	return nil, nil
}

func (p *epbsProposalProvider) EPBSProposal(_ context.Context,
	opts *api.EPBSProposalOpts,
) (
	*api.Response[*api.VersionedEPBSProposal],
	error,
) {
	p.opts = opts
	if p.release != nil {
		<-p.release
	}
	if p.nilResponse {
		return nil, nil
	}

	return &api.Response[*api.VersionedEPBSProposal]{Data: p.proposal}, nil
}

// TestEPBSProposalAcceptsBuilderBackedProposal proves that a proposal the beacon node
// awarded to a P2P builder is a valid result even though Vouch asked for the payload: the
// node never holds a builder's payload, so it cannot return one.
func TestEPBSProposalAcceptsBuilderBackedProposal(t *testing.T) {
	ctx := context.Background()
	includePayload := true
	proposal := gloasEPBSProposalWithoutPayload(bellatrix.ExecutionAddress{0x01})
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"builder": &epbsProposalProvider{proposal: proposal},
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, IncludePayload: &includePayload})
	require.NoError(t, err)
	require.Same(t, proposal, response.Data)
}

// TestEPBSProposalSkipsBuilderBackedProposalWithPayload proves that a builder-backed
// proposal claiming to carry an execution payload is rejected: the two cannot both be true.
func TestEPBSProposalSkipsBuilderBackedProposalWithPayload(t *testing.T) {
	ctx := context.Background()
	includePayload := true
	inconsistent := gloasEPBSProposal(bellatrix.ExecutionAddress{0x01})
	inconsistent.GloasContents.Block.Body.SignedExecutionPayloadBid.Message.BuilderIndex = 7
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"inconsistent": &epbsProposalProvider{proposal: inconsistent},
		}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, IncludePayload: &includePayload})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
}

// gloasEPBSProposalWithoutPayload returns a builder-backed proposal, which carries only
// the block: the winning builder reveals the payload itself.
func gloasEPBSProposalWithoutPayload(feeRecipient bellatrix.ExecutionAddress) *api.VersionedEPBSProposal {
	proposal := gloasEPBSProposal(feeRecipient)
	proposal.Gloas = proposal.GloasContents.Block
	proposal.GloasContents = nil
	proposal.ExecutionPayloadIncluded = false
	proposal.Gloas.Body.SignedExecutionPayloadBid.Message.BuilderIndex = 7

	return proposal
}

// TestEPBSProposalForwardsBuilderConfigUnchanged proves that the strategy passes the
// operator's auction policy to each beacon node as given: the boost is the beacon node's to
// apply, and applying it again here would express a preference nobody configured.
func TestEPBSProposalForwardsBuilderConfigUnchanged(t *testing.T) {
	ctx := context.Background()
	provider := &epbsProposalProvider{proposal: gloasEPBSProposal(bellatrix.ExecutionAddress{0x01})}
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"one": provider,
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	builderConfig := &gloas.BuilderConfig{
		MinBid:             phase0.Gwei(12345),
		BuilderBoostFactor: 91,
		Builders:           []*gloas.BuilderEntry{},
	}
	_, err = service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, BuilderConfig: builderConfig})
	require.NoError(t, err)

	require.NotNil(t, provider.opts)
	require.Equal(t, builderConfig, provider.opts.BuilderConfig)
}

// TestEPBSProposalSkipsSelfBuiltProposalWithoutPayload proves that a self-built proposal
// that did not carry the requested payload is discarded: only its producing node could
// publish it, so it is unusable here.
func TestEPBSProposalSkipsSelfBuiltProposalWithoutPayload(t *testing.T) {
	ctx := context.Background()
	includePayload := true
	selfBuilt := gloasEPBSProposalWithoutPayload(bellatrix.ExecutionAddress{0x01})
	selfBuilt.Gloas.Body.SignedExecutionPayloadBid.Message.BuilderIndex = gloas.BuilderIndex(^uint64(0))
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"self-built": &epbsProposalProvider{proposal: selfBuilt},
		}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, IncludePayload: &includePayload})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
}
