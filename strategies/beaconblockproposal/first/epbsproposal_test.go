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
	"errors"
	"runtime"
	"strings"
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
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/strategies/beaconblockproposal/first"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestEPBSProposalFansOutTheSameBuilderConfig(t *testing.T) {
	ctx := context.Background()
	config := &gloas.BuilderConfig{MinBid: 12, BuilderBoostFactor: 100, Builders: []*gloas.BuilderEntry{}}
	ready := make(chan struct{})
	var readyOnce sync.Once
	var mu sync.Mutex
	received := make([]*api.EPBSProposalOpts, 0, 2)
	provider := func(feeRecipient byte) eth2client.MultiForkProposalProvider {
		return &fanoutEPBSProposalProvider{
			proposal:  gloasEPBSProposal(bellatrix.ExecutionAddress{feeRecipient}),
			ready:     ready,
			readyOnce: &readyOnce,
			mu:        &mu,
			received:  &received,
		}
	}
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]eth2client.MultiForkProposalProvider{
			"one": provider(0x01),
			"two": provider(0x02),
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	_, err = service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, BuilderConfig: config})
	require.NoError(t, err)
	require.Len(t, received, 2)
	for i := range received {
		require.Same(t, config, received[i].BuilderConfig)
	}
}

type fanoutEPBSProposalProvider struct {
	proposal  *api.VersionedEPBSProposal
	ready     chan struct{}
	readyOnce *sync.Once
	mu        *sync.Mutex
	received  *[]*api.EPBSProposalOpts
}

func (p *fanoutEPBSProposalProvider) EPBSProposal(ctx context.Context, opts *api.EPBSProposalOpts) (*api.Response[*api.VersionedEPBSProposal], error) {
	p.mu.Lock()
	*p.received = append(*p.received, opts)
	if len(*p.received) == cap(*p.received) {
		p.readyOnce.Do(func() {
			close(p.ready)
		})
	}
	p.mu.Unlock()

	select {
	case <-p.ready:
		return &api.Response[*api.VersionedEPBSProposal]{Data: p.proposal}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *fanoutEPBSProposalProvider) Proposal(context.Context, *api.ProposalOpts) (*api.Response[*api.VersionedProposal], error) {
	return nil, nil
}

func TestEPBSProposalAcceptsUnknownValue(t *testing.T) {
	ctx := context.Background()

	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"one": &epbsProposalProvider{proposal: gloasEPBSProposal(bellatrix.ExecutionAddress{0x01})},
		},
		time.Second,
	)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot: phase0.Slot(1),
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.NotNil(t, response.Data)
	require.Nil(t, response.Data.ExecutionValue)
}

func TestNewRejectsEmptyProviders(t *testing.T) {
	ctx := context.Background()

	service, err := first.New(ctx,
		first.WithProposalProviders(map[string]eth2client.MultiForkProposalProvider{}),
	)
	require.Nil(t, service)
	require.EqualError(t, err, "problem with parameters: no beacon block proposal providers specified")
}

func TestProposalReturnsProviderError(t *testing.T) {
	ctx := context.Background()
	providerErr := errors.New("proposal failed")
	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"one": &epbsProposalProvider{proposalErr: providerErr},
		},
		100*time.Millisecond,
	)

	response, err := service.Proposal(ctx, &api.ProposalOpts{})
	require.Nil(t, response)
	require.ErrorIs(t, err, providerErr)
}

func TestProposalReturnsProposalAfterProviderError(t *testing.T) {
	ctx := context.Background()
	proposal := &api.VersionedProposal{}
	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"error": &epbsProposalProvider{proposalErr: errors.New("proposal failed")},
			"valid": &epbsProposalProvider{legacyProposal: proposal},
		},
		time.Second,
	)

	response, err := service.Proposal(ctx, &api.ProposalOpts{})
	require.NoError(t, err)
	require.Same(t, proposal, response.Data)
}

func TestProposalReturnsCompletedErrorsAtTimeout(t *testing.T) {
	ctx := context.Background()
	providerErr := errors.New("proposal failed")
	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"error":   &epbsProposalProvider{proposalErr: providerErr},
			"pending": &epbsProposalProvider{proposalWaitForCancellation: true},
		},
		20*time.Millisecond,
	)

	response, err := service.Proposal(ctx, &api.ProposalOpts{})
	require.Nil(t, response)
	require.ErrorIs(t, err, providerErr)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestProposalReturnsAllProviderErrors(t *testing.T) {
	ctx := context.Background()
	firstErr := errors.New("first proposal failed")
	secondErr := errors.New("second proposal failed")
	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"one": &epbsProposalProvider{proposalErr: firstErr},
			"two": &epbsProposalProvider{proposalErr: secondErr},
		},
		time.Second,
	)

	response, err := service.Proposal(ctx, &api.ProposalOpts{})
	require.Nil(t, response)
	require.ErrorIs(t, err, firstErr)
	require.ErrorIs(t, err, secondErr)
}

func TestProposalExpandsClientGraffiti(t *testing.T) {
	tests := []struct {
		name string
		epbs bool
	}{
		{
			name: "Proposal",
		},
		{
			name: "EPBSProposal",
			epbs: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			provider := &epbsProposalProvider{
				proposal:       gloasEPBSProposal(bellatrix.ExecutionAddress{0x01}),
				legacyProposal: &api.VersionedProposal{},
				client:         "prysm",
				graffiti:       make(chan [32]byte, 1),
			}
			service := newTestService(ctx, t,
				map[string]eth2client.MultiForkProposalProvider{
					"one": provider,
				},
				time.Second,
			)
			var graffiti [32]byte
			copy(graffiti[:], "configured {{CLIENT}}")

			var err error
			if test.epbs {
				_, err = service.EPBSProposal(ctx, &api.EPBSProposalOpts{Graffiti: graffiti})
			} else {
				_, err = service.Proposal(ctx, &api.ProposalOpts{Graffiti: graffiti})
			}
			require.NoError(t, err)
			var expected [32]byte
			copy(expected[:], "configured prysm")
			require.Equal(t, expected, <-provider.graffiti)
		})
	}
}

func TestEPBSProposalReturnsProviderError(t *testing.T) {
	ctx := context.Background()
	providerErr := errors.New("proposal failed")
	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"one": &epbsProposalProvider{err: providerErr},
		},
		100*time.Millisecond,
	)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.Nil(t, response)
	require.ErrorIs(t, err, providerErr)
}

func TestEPBSProposalReturnsCompletedErrorsAtTimeout(t *testing.T) {
	ctx := context.Background()
	providerErr := errors.New("proposal failed")
	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"error":   &epbsProposalProvider{err: providerErr},
			"pending": &epbsProposalProvider{waitForCancellation: true},
		},
		20*time.Millisecond,
	)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.Nil(t, response)
	require.ErrorIs(t, err, providerErr)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestEPBSProposalReturnsAllProviderErrors(t *testing.T) {
	ctx := context.Background()
	firstErr := errors.New("first proposal failed")
	secondErr := errors.New("second proposal failed")
	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"one": &epbsProposalProvider{err: firstErr},
			"two": &epbsProposalProvider{err: secondErr},
		},
		time.Second,
	)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.Nil(t, response)
	require.ErrorIs(t, err, firstErr)
	require.ErrorIs(t, err, secondErr)
}

func TestEPBSProposalDoesNotLeaveLateProvidersBlocked(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"fast":  &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}},
			"late1": &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}, release: release},
			"late2": &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}, release: release},
		},
		time.Second,
	)

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

func TestEPBSProposalGatesBuilderBidsByProviderReadiness(t *testing.T) {
	builderBid := func(proposerIndex phase0.ValidatorIndex) *api.VersionedEPBSProposal {
		proposal := gloasEPBSProposalWithoutPayload(bellatrix.ExecutionAddress{0x01})
		proposal.Gloas.ProposerIndex = proposerIndex
		proposal.Gloas.Body.SignedExecutionPayloadBid.Message.BuilderIndex = 1

		return proposal
	}
	readyBid := builderBid(7)
	const unreadyErr = "failed to obtain ePBS beacon block proposal: ready: builder-backed ePBS proposal from provider without current preferences"
	tests := []struct {
		name      string
		providers map[string]*api.VersionedEPBSProposal
		ready     map[readyDuty]bool
		expected  *api.VersionedEPBSProposal
		err       string
	}{
		{
			name:      "Ready",
			providers: map[string]*api.VersionedEPBSProposal{"ready": readyBid},
			ready:     map[readyDuty]bool{{provider: "ready", slot: 1, index: 7}: true},
			expected:  readyBid,
		},
		{
			name:      "Unready",
			providers: map[string]*api.VersionedEPBSProposal{"ready": builderBid(7)},
			err:       unreadyErr,
		},
		{
			name:      "ReadyForOtherSlot",
			providers: map[string]*api.VersionedEPBSProposal{"ready": builderBid(7)},
			ready:     map[readyDuty]bool{{provider: "ready", slot: 2, index: 7}: true},
			err:       unreadyErr,
		},
		{
			name:      "ReadyForOtherValidator",
			providers: map[string]*api.VersionedEPBSProposal{"ready": builderBid(7)},
			ready:     map[readyDuty]bool{{provider: "ready", slot: 1, index: 8}: true},
			err:       unreadyErr,
		},
		{
			name: "UnreadyProviderSkipped",
			providers: map[string]*api.VersionedEPBSProposal{
				"ready":   readyBid,
				"unready": builderBid(7),
			},
			ready:    map[readyDuty]bool{{provider: "ready", slot: 1, index: 7}: true},
			expected: readyBid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			providers := make(map[string]eth2client.MultiForkProposalProvider, len(test.providers))
			for name, proposal := range test.providers {
				providers[name] = &epbsProposalProvider{proposal: proposal}
			}
			service, err := first.New(ctx,
				first.WithLogLevel(zerolog.Disabled),
				first.WithClientMonitor(nullmetrics.New()),
				first.WithProposalProviders(providers),
				first.WithProviderReadiness(&providerReadiness{ready: test.ready}),
				first.WithTimeout(time.Second),
			)
			require.NoError(t, err)

			response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1})
			if test.err != "" {
				require.Nil(t, response)
				require.EqualError(t, err, test.err)

				return
			}
			require.NoError(t, err)
			require.Same(t, test.expected, response.Data)
		})
	}
}

func TestEPBSProposalAcceptsSelfBuiltProposalFromUnreadyProvider(t *testing.T) {
	ctx := context.Background()
	proposal := gloasEPBSProposal(bellatrix.ExecutionAddress{0x01})
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]eth2client.MultiForkProposalProvider{
			"unready": &epbsProposalProvider{proposal: proposal},
		}),
		first.WithProviderReadiness(&providerReadiness{}),
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
	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"excluded": &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}},
		},
		10*time.Millisecond,
	)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{IncludePayload: &includePayload})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal: excluded: ePBS proposal excludes requested execution payload")
}

func TestEPBSProposalSkipsZeroFeeRecipient(t *testing.T) {
	ctx := context.Background()
	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"zero-fee": &epbsProposalProvider{proposal: gloasEPBSProposal(bellatrix.ExecutionAddress{})},
		},
		10*time.Millisecond,
	)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal: zero-fee: beacon block obtained with 0 fee recipient")
}

func TestEPBSProposalSkipsNilResponse(t *testing.T) {
	ctx := context.Background()
	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"nil": &epbsProposalProvider{nilResponse: true},
		},
		10*time.Millisecond,
	)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal: nil: beacon node returned no ePBS proposal response")
}

func TestEPBSProposalSkipsMalformedGloasProposal(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		proposal *api.VersionedEPBSProposal
		err      string
	}{
		{
			name: "Nil",
			err:  "failed to obtain ePBS beacon block proposal: malformed: beacon node returned no ePBS proposal",
		},
		{
			name: "GloasWithoutBlock",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
			},
			err: "failed to obtain ePBS beacon block proposal: malformed: ePBS proposal has no execution payload bid",
		},
		{
			name: "GloasContentsWithoutBlock",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
				GloasContents:            &apiv1gloas.BlockContents{},
			},
			err: "failed to obtain ePBS beacon block proposal: malformed: ePBS proposal has no execution payload bid",
		},
		{
			name: "GloasContentsNil",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
			},
			err: "failed to obtain ePBS beacon block proposal: malformed: ePBS proposal has no execution payload bid",
		},
		{
			name: "BlockWithoutBody",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
				Gloas:   &gloas.BeaconBlock{},
			},
			err: "failed to obtain ePBS beacon block proposal: malformed: ePBS proposal has no execution payload bid",
		},
		{
			name: "BodyWithoutBid",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
				Gloas: &gloas.BeaconBlock{
					Body: &gloas.BeaconBlockBody{},
				},
			},
			err: "failed to obtain ePBS beacon block proposal: malformed: ePBS proposal has no execution payload bid",
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
			err: "failed to obtain ePBS beacon block proposal: malformed: ePBS proposal has no execution payload bid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newTestService(ctx, t,
				map[string]eth2client.MultiForkProposalProvider{
					"malformed": &epbsProposalProvider{proposal: test.proposal},
				},
				10*time.Millisecond,
			)

			response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
			require.Nil(t, response)
			require.EqualError(t, err, test.err)
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
	service := newTestService(ctx, t,
		map[string]eth2client.MultiForkProposalProvider{
			"excluded": &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}},
			"included": &epbsProposalProvider{proposal: included, release: release},
		},
		time.Second,
	)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{IncludePayload: &includePayload})
	require.NoError(t, err)
	require.Same(t, included, response.Data)
}

func newTestService(ctx context.Context,
	t *testing.T,
	providers map[string]eth2client.MultiForkProposalProvider,
	timeout time.Duration,
) *first.Service {
	t.Helper()

	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(providers),
		first.WithTimeout(timeout),
	)
	require.NoError(t, err)

	return service
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
						Message: &gloas.ExecutionPayloadBid{BuilderIndex: gloas.BuilderIndexSelfBuild, FeeRecipient: feeRecipient},
					},
				},
			},
		},
	}
}

type readyDuty struct {
	provider string
	slot     phase0.Slot
	index    phase0.ValidatorIndex
}

type providerReadiness struct {
	ready map[readyDuty]bool
}

func (p *providerReadiness) ProviderReady(provider string, slot phase0.Slot, index phase0.ValidatorIndex) bool {
	return p.ready[readyDuty{provider: provider, slot: slot, index: index}]
}

type epbsProposalProvider struct {
	proposal                    *api.VersionedEPBSProposal
	legacyProposal              *api.VersionedProposal
	release                     <-chan struct{}
	nilResponse                 bool
	client                      string
	graffiti                    chan [32]byte
	err                         error
	proposalErr                 error
	waitForCancellation         bool
	proposalWaitForCancellation bool
	opts                        *api.EPBSProposalOpts
}

func (p *epbsProposalProvider) Proposal(ctx context.Context, opts *api.ProposalOpts) (*api.Response[*api.VersionedProposal], error) {
	if p.proposalWaitForCancellation {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if p.graffiti != nil {
		p.graffiti <- opts.Graffiti
	}
	if p.proposalErr != nil {
		return nil, p.proposalErr
	}

	return &api.Response[*api.VersionedProposal]{Data: p.legacyProposal}, nil
}

func (p *epbsProposalProvider) EPBSProposal(ctx context.Context,
	opts *api.EPBSProposalOpts,
) (
	*api.Response[*api.VersionedEPBSProposal],
	error,
) {
	p.opts = opts
	if p.release != nil {
		<-p.release
	}
	if p.waitForCancellation {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if p.graffiti != nil {
		p.graffiti <- opts.Graffiti
	}
	if p.err != nil {
		return nil, p.err
	}
	if p.nilResponse {
		return nil, nil
	}

	return &api.Response[*api.VersionedEPBSProposal]{Data: p.proposal}, nil
}

func (p *epbsProposalProvider) NodeClient(context.Context) (*api.Response[string], error) {
	return &api.Response[string]{Data: p.client}, nil
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
		first.WithProposalProviders(map[string]eth2client.MultiForkProposalProvider{
			"builder": &epbsProposalProvider{proposal: proposal},
		}),
		first.WithProviderReadiness(&providerReadiness{ready: map[readyDuty]bool{{provider: "builder", slot: 1}: true}}),
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
		first.WithProposalProviders(map[string]eth2client.MultiForkProposalProvider{
			"inconsistent": &epbsProposalProvider{proposal: inconsistent},
		}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, IncludePayload: &includePayload})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal: inconsistent: builder-backed ePBS proposal carries an execution payload")
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
		first.WithProposalProviders(map[string]eth2client.MultiForkProposalProvider{
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
	selfBuilt.Gloas.Body.SignedExecutionPayloadBid.Message.BuilderIndex = gloas.BuilderIndexSelfBuild
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]eth2client.MultiForkProposalProvider{
			"self-built": &epbsProposalProvider{proposal: selfBuilt},
		}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, IncludePayload: &includePayload})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal: self-built: ePBS proposal excludes requested execution payload")
}
