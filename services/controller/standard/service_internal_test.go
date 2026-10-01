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

package standard

import (
	"context"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	mockattestationaggregator "github.com/attestantio/vouch/services/attestationaggregator/mock"
	mockattester "github.com/attestantio/vouch/services/attester/mock"
	mockbeaconblockproposer "github.com/attestantio/vouch/services/beaconblockproposer/mock"
	mockbeaconcommitteesubscriber "github.com/attestantio/vouch/services/beaconcommitteesubscriber/mock"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	alwaysmultiinstance "github.com/attestantio/vouch/services/multiinstance/always"
	mockproposalpreparer "github.com/attestantio/vouch/services/proposalpreparer/mock"
	"github.com/attestantio/vouch/services/proposerpreferences"
	mockscheduler "github.com/attestantio/vouch/services/scheduler/mock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestNewSeedsProposerPreferencesDependentRoots(t *testing.T) {
	dutiesProvider := &headEventProposerDutiesProvider{epochs: make(chan phase0.Epoch, 16)}
	newProposerPreferencesController(t, &recordingEventsProvider{},
		WithProposerDutiesV2Provider(dutiesProvider),
		WithProposerPreferences(&headEventProposerPreferences{duties: make(chan *proposerpreferences.Duty, 16)}),
		WithExecutionConfigProvider(&recordingExecutionConfigProvider{}),
	)

	epochs := []phase0.Epoch{receiveProposerPreferencesEpoch(t, dutiesProvider.epochs), receiveProposerPreferencesEpoch(t, dutiesProvider.epochs)}
	require.ElementsMatch(t, []phase0.Epoch{0, 1}, epochs)
}

func TestNewSubscribesToHeadV2OnlyForProposerPreferences(t *testing.T) {
	disabled := &recordingEventsProvider{}
	newProposerPreferencesController(t, disabled)
	require.Equal(t, []string{"block", "head"}, disabled.opts.Topics)
	require.Nil(t, disabled.opts.HeadV2Handler)

	enabled := &recordingEventsProvider{}
	newProposerPreferencesController(t, enabled,
		WithProposerDutiesV2Provider(&headEventProposerDutiesProvider{epochs: make(chan phase0.Epoch, 16)}),
		WithProposerPreferences(&headEventProposerPreferences{duties: make(chan *proposerpreferences.Duty, 16)}),
		WithExecutionConfigProvider(&recordingExecutionConfigProvider{}),
	)
	require.Equal(t, []string{"block", "head", "head_v2"}, enabled.opts.Topics)
	require.NotNil(t, enabled.opts.HeadV2Handler)
}

func TestNewSubscribesToPayloadEventsOnlyForGloasPayloadAttestation(t *testing.T) {
	ctx := context.Background()
	gloasSpecProvider := &gloasSpecProvider{SpecProvider: mock.NewSpecProvider()}
	gloasChainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(gloasSpecProvider),
	)
	require.NoError(t, err)
	gloas := []Parameter{WithSpecProvider(gloasSpecProvider), WithChainTimeService(gloasChainTime)}
	payloadAttestation := []Parameter{
		WithPTCDutiesProvider(&recordingPTCDutiesProvider{}),
		WithPayloadAttester(&recordingPayloadAttester{}),
	}

	tests := []struct {
		name      string
		params    []Parameter
		subscribe bool
	}{
		{
			name:      "GloasPayloadAttestation",
			params:    append(append([]Parameter{}, gloas...), payloadAttestation...),
			subscribe: true,
		},
		{
			name:   "GloasNotScheduled",
			params: payloadAttestation,
		},
		{
			name:   "NoPayloadAttester",
			params: gloas,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payloadEvents := &recordingEventsProvider{}
			newProposerPreferencesController(t, &recordingEventsProvider{},
				append([]Parameter{WithPayloadEventsProvider(payloadEvents)}, test.params...)...,
			)

			if test.subscribe {
				require.NotNil(t, payloadEvents.opts)
				require.Equal(t, []string{"execution_payload_available"}, payloadEvents.opts.Topics)
			} else {
				require.Nil(t, payloadEvents.opts)
			}
		})
	}
}

// gloasSpecProvider schedules the Gloas fork at genesis.
type gloasSpecProvider struct {
	eth2client.SpecProvider
}

func (p *gloasSpecProvider) Spec(ctx context.Context, opts *api.SpecOpts) (*api.Response[map[string]any], error) {
	response, err := p.SpecProvider.Spec(ctx, opts)
	if err != nil {
		return nil, err
	}
	response.Data["GLOAS_FORK_EPOCH"] = uint64(0)

	return response, nil
}

func newProposerPreferencesController(t *testing.T, eventsProvider *recordingEventsProvider, params ...Parameter) {
	t.Helper()
	ctx := context.Background()
	specProvider := &seedLookaheadSpecProvider{SpecProvider: mock.NewSpecProvider()}
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	multiInstance, err := alwaysmultiinstance.New(ctx)
	require.NoError(t, err)

	_, err = New(ctx, append([]Parameter{
		WithLogLevel(zerolog.Disabled),
		WithMonitor(nullmetrics.New()),
		WithSpecProvider(specProvider),
		WithChainTimeService(chainTime),
		WithProposerDutiesProvider(mock.NewProposerDutiesProvider()),
		WithAttesterDutiesProvider(mock.NewAttesterDutiesProvider()),
		WithEventsProvider(eventsProvider),
		WithValidatingAccountsProvider(mockaccountmanager.NewValidatingAccountsProvider()),
		WithProposalsPreparer(mockproposalpreparer.New()),
		WithScheduler(mockscheduler.New()),
		WithAttester(mockattester.New()),
		WithBeaconBlockProposer(mockbeaconblockproposer.New()),
		WithBeaconCommitteeSubscriber(mockbeaconcommitteesubscriber.New()),
		WithAttestationAggregator(mockattestationaggregator.New()),
		WithAccountsRefresher(mockaccountmanager.NewRefresher()),
		WithBlockToSlotSetter(mockcache.New(map[phase0.Root]phase0.Slot{}).(cache.BlockRootToSlotSetter)),
		WithBeaconBlockHeadersProvider(mock.NewBeaconBlockHeadersProvider()),
		WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
		WithMultiInstance(multiInstance),
	}, params...)...)
	require.NoError(t, err)
}

type seedLookaheadSpecProvider struct {
	eth2client.SpecProvider
}

func (p *seedLookaheadSpecProvider) Spec(ctx context.Context, opts *api.SpecOpts) (*api.Response[map[string]any], error) {
	response, err := p.SpecProvider.Spec(ctx, opts)
	if err != nil {
		return nil, err
	}
	response.Data["MIN_SEED_LOOKAHEAD"] = uint64(1)

	return response, nil
}

type recordingEventsProvider struct {
	opts *api.EventsOpts
}

func (p *recordingEventsProvider) Events(_ context.Context, opts *api.EventsOpts) error {
	p.opts = opts

	return nil
}
