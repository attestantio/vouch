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
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
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
	dutiesProvider := &v2RecordingProposerDutiesProvider{epochs: make(chan phase0.Epoch, 16)}

	_, err = New(ctx,
		WithLogLevel(zerolog.Disabled),
		WithMonitor(nullmetrics.New()),
		WithSpecProvider(specProvider),
		WithChainTimeService(chainTime),
		WithProposerDutiesProvider(dutiesProvider),
		WithAttesterDutiesProvider(mock.NewAttesterDutiesProvider()),
		WithEventsProvider(mock.NewEventsProvider()),
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
		WithProposerPreferences(&headEventProposerPreferences{duties: make(chan *proposerpreferences.Duty, 16)}),
		WithExecutionConfigProvider(&recordingExecutionConfigProvider{}),
	)
	require.NoError(t, err)

	epochs := []phase0.Epoch{receiveEpoch(t, dutiesProvider.epochs), receiveEpoch(t, dutiesProvider.epochs)}
	require.ElementsMatch(t, []phase0.Epoch{0, 1}, epochs)
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

type v2RecordingProposerDutiesProvider struct {
	mock.ProposerDutiesProvider

	epochs chan phase0.Epoch
}

func (p *v2RecordingProposerDutiesProvider) ProposerDutiesV2(_ context.Context, opts *api.ProposerDutiesOpts) (*api.Response[[]*apiv1.ProposerDuty], error) {
	p.epochs <- opts.Epoch

	return &api.Response[[]*apiv1.ProposerDuty]{Data: []*apiv1.ProposerDuty{}, Metadata: map[string]any{}}, nil
}

func receiveEpoch(t *testing.T, epochs <-chan phase0.Epoch) phase0.Epoch {
	t.Helper()
	select {
	case epoch := <-epochs:
		return epoch
	case <-time.After(time.Second):
		require.FailNow(t, "timed out waiting for proposer duties v2 request")
	}

	return 0
}
