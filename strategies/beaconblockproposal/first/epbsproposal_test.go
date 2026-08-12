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

package first_test

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	mockconsensusclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/strategies/beaconblockproposal/first"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestEPBSProposal(t *testing.T) {
	ctx := context.Background()
	provider, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)

	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"one": provider,
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

type epbsProposalProvider struct {
	proposal *api.VersionedEPBSProposal
	release  <-chan struct{}
}

func (p *epbsProposalProvider) Proposal(_ context.Context, _ *api.ProposalOpts) (*api.Response[*api.VersionedProposal], error) {
	return nil, nil
}

func (p *epbsProposalProvider) EPBSProposal(_ context.Context,
	_ *api.EPBSProposalOpts,
) (
	*api.Response[*api.VersionedEPBSProposal],
	error,
) {
	if p.release != nil {
		<-p.release
	}

	return &api.Response[*api.VersionedEPBSProposal]{Data: p.proposal}, nil
}
