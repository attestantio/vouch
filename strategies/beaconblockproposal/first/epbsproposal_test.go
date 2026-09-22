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

func TestEPBSProposal(t *testing.T) {
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

func gloasEPBSProposal(feeRecipient bellatrix.ExecutionAddress) *api.VersionedEPBSProposal {
	return &api.VersionedEPBSProposal{
		Version:                  spec.DataVersionGloas,
		ExecutionPayloadIncluded: true,
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
