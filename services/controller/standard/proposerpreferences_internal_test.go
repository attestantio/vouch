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

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/proposerpreferences"
	"github.com/attestantio/vouch/testutil"
	"github.com/stretchr/testify/require"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestPublishProposerPreferencesPublishesFirstGloasEpoch(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)

	provider := &recordingProposerDutiesProvider{
		duties:   []*apiv1.ProposerDuty{{Slot: 160, ValidatorIndex: 3}},
		metadata: map[string]any{"dependent_root": phase0.Root{0x01}},
	}
	preferences := &recordingProposerPreferences{}
	service := &Service{
		chainTimeService:             &recordingChainTime{currentEpoch: 4, slotDuration: time.Second, slotsPerEpoch: 32},
		proposerDutiesProvider:       provider,
		proposerDutiesV2Provider:     provider,
		validatingAccountsProvider:   &proposerPreferencesAccountsProvider{accounts: accounts},
		executionConfigProvider:      &recordingExecutionConfigProvider{config: &beaconblockproposer.ProposerConfig{FeeRecipient: bellatrix.ExecutionAddress{0x02}, GasLimit: 30_000_000}},
		proposerPreferences:          preferences,
		gloasForkEpoch:               5,
		proposerPreferencesLookahead: 1,
	}

	service.publishProposerPreferences(ctx, 5, phase0.Root{0x01})

	require.Zero(t, provider.v1Calls)
	require.Equal(t, 1, provider.v2Calls)
	require.Equal(t, phase0.Epoch(5), provider.epoch)
	require.Equal(t, []*proposerpreferences.Duty{proposerpreferences.NewDuty(
		phase0.Root{0x01},
		160,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	)}, preferences.duties)
}

func TestHandleHeadV2EventUsesEpochDependentRootsAcrossBoundary(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{100}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)

	rootA := testutil.HexToRoot("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	rootB := testutil.HexToRoot("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	rootC := testutil.HexToRoot("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	require.NotZero(t, rootA)
	require.NotZero(t, rootB)
	require.NotZero(t, rootC)
	require.NotEqual(t, rootA, rootB)
	require.NotEqual(t, rootB, rootC)
	require.NotEqual(t, rootA, rootC)

	const gasLimit = 30_000_000
	feeRecipient := bellatrix.ExecutionAddress{0x89, 0x43, 0x54, 0x51, 0x77, 0x80, 0x6e, 0xd1, 0x7b, 0x9f, 0x23, 0xf0, 0xa2, 0x1e, 0xe5, 0x94, 0x8e, 0xca, 0xa7, 0x76}
	provider := &headEventProposerDutiesProvider{
		responses: map[phase0.Epoch]*api.Response[[]*apiv1.ProposerDuty]{
			6: {Data: []*apiv1.ProposerDuty{{Slot: 209, ValidatorIndex: 100}}, Metadata: map[string]any{"dependent_root": rootA}},
			7: {Data: []*apiv1.ProposerDuty{{Slot: 225, ValidatorIndex: 100}}, Metadata: map[string]any{"dependent_root": rootB}},
			8: {Data: []*apiv1.ProposerDuty{{Slot: 257, ValidatorIndex: 100}}, Metadata: map[string]any{"dependent_root": rootC}},
		},
		epochs: make(chan phase0.Epoch, 16),
	}
	preferences := &headEventProposerPreferences{duties: make(chan *proposerpreferences.Duty, 16)}
	chainTime := &recordingChainTime{currentEpoch: 6, slotsPerEpoch: 32}
	service := &Service{
		chainTimeService:             chainTime,
		proposerDutiesV2Provider:     provider,
		validatingAccountsProvider:   &proposerPreferencesAccountsProvider{accounts: accounts},
		executionConfigProvider:      &recordingExecutionConfigProvider{config: &beaconblockproposer.ProposerConfig{FeeRecipient: feeRecipient, GasLimit: gasLimit}},
		proposerPreferences:          preferences,
		gloasForkEpoch:               5,
		proposerPreferencesLookahead: 1,
		slotsPerEpoch:                32,
	}

	service.HandleHeadV2Event(ctx, &apiv1.HeadEventV2{
		Slot:                      192,
		CurrentEpochDependentRoot: rootA,
		NextEpochDependentRoot:    rootB,
	})

	require.Equal(t, phase0.Epoch(6), receiveProposerPreferencesEpoch(t, provider.epochs))
	require.Equal(t, proposerpreferences.NewDuty(rootA, 209, 100, accounts[100], feeRecipient, gasLimit), receiveProposerPreferencesDuty(t, preferences.duties))
	require.Equal(t, phase0.Epoch(7), receiveProposerPreferencesEpoch(t, provider.epochs))
	require.Equal(t, proposerpreferences.NewDuty(rootB, 225, 100, accounts[100], feeRecipient, gasLimit), receiveProposerPreferencesDuty(t, preferences.duties))
	waitForProposerPreferencesPublication(t, service)

	chainTime.currentEpoch = 7
	service.HandleHeadV2Event(ctx, &apiv1.HeadEventV2{
		Slot:                      224,
		CurrentEpochDependentRoot: rootB,
		NextEpochDependentRoot:    rootC,
	})

	require.Equal(t, phase0.Epoch(7), receiveProposerPreferencesEpoch(t, provider.epochs))
	require.Equal(t, proposerpreferences.NewDuty(rootB, 225, 100, accounts[100], feeRecipient, gasLimit), receiveProposerPreferencesDuty(t, preferences.duties))
	require.Equal(t, phase0.Epoch(8), receiveProposerPreferencesEpoch(t, provider.epochs))
	require.Equal(t, proposerpreferences.NewDuty(rootC, 257, 100, accounts[100], feeRecipient, gasLimit), receiveProposerPreferencesDuty(t, preferences.duties))
	waitForProposerPreferencesPublication(t, service)
}

func TestChangedHeadV2RootInvalidatesUntilClassicHeadRefreshesCorrectedPreferences(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{100}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)

	rootA := testutil.HexToRoot("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	rootB := testutil.HexToRoot("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	rootC := testutil.HexToRoot("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	provider := &headEventProposerDutiesProvider{
		responses: map[phase0.Epoch]*api.Response[[]*apiv1.ProposerDuty]{
			6: {Data: []*apiv1.ProposerDuty{{Slot: 209, ValidatorIndex: 100}}, Metadata: map[string]any{"dependent_root": rootA}},
		},
		epochs: make(chan phase0.Epoch, 16),
	}
	preferences := &headEventProposerPreferences{
		duties:      make(chan *proposerpreferences.Duty, 16),
		invalidated: make(chan slotRange, 4),
	}
	chainTime := &recordingChainTime{currentEpoch: 6, slotsPerEpoch: 32}
	service := &Service{
		chainTimeService:                  chainTime,
		proposerDutiesV2Provider:          provider,
		validatingAccountsProvider:        &proposerPreferencesAccountsProvider{accounts: accounts},
		executionConfigProvider:           &recordingExecutionConfigProvider{config: &beaconblockproposer.ProposerConfig{}},
		proposerPreferences:               preferences,
		gloasForkEpoch:                    5,
		proposerPreferencesLookahead:      1,
		slotsPerEpoch:                     32,
		proposerPreferencesDependentRoots: map[phase0.Epoch]phase0.Root{6: rootA},
	}

	service.HandleHeadV2Event(ctx, &apiv1.HeadEventV2{
		Slot:                      192,
		CurrentEpochDependentRoot: rootB,
		NextEpochDependentRoot:    rootC,
	})

	require.Equal(t, slotRange{from: 192, to: 223, root: rootB}, receiveInvalidatedSlotRange(t, preferences.invalidated))
	waitForProposerPreferencesPublication(t, service)
	assertNoProposerPreferencesDuty(t, preferences.duties)

	provider.responses[6] = &api.Response[[]*apiv1.ProposerDuty]{
		Data:     []*apiv1.ProposerDuty{{Slot: 209, ValidatorIndex: 100}},
		Metadata: map[string]any{"dependent_root": rootB},
	}
	service.HandleHeadEvent(ctx, &apiv1.HeadEvent{Slot: 192})

	require.Equal(t, proposerpreferences.NewDuty(rootB, 209, 100, accounts[100], bellatrix.ExecutionAddress{}, 0), receiveProposerPreferencesDuty(t, preferences.duties))
	waitForProposerPreferencesPublication(t, service)
}

func TestPublishProposerPreferencesPrunesPastSlots(t *testing.T) {
	preferences := &recordingProposerPreferences{}
	service := &Service{
		chainTimeService:             &recordingChainTime{currentEpoch: 4, slotsPerEpoch: 32},
		proposerDutiesProvider:       &recordingProposerDutiesProvider{},
		proposerDutiesV2Provider:     &recordingProposerDutiesProvider{},
		proposerPreferences:          preferences,
		executionConfigProvider:      &recordingExecutionConfigProvider{},
		gloasForkEpoch:               5,
		proposerPreferencesLookahead: 1,
	}

	service.publishProposerPreferences(context.Background(), 4, phase0.Root{0x01})

	require.Equal(t, []phase0.Slot{128}, preferences.prunedSlots)
}

func TestPublishProposerPreferencesRejectsDutiesWithoutDependentRoot(t *testing.T) {
	provider := &recordingProposerDutiesProvider{duties: []*apiv1.ProposerDuty{{Slot: 160, ValidatorIndex: 3}}}
	preferences := &recordingProposerPreferences{}
	service := &Service{
		chainTimeService:             &recordingChainTime{currentEpoch: 4, slotsPerEpoch: 32},
		proposerDutiesProvider:       provider,
		proposerDutiesV2Provider:     provider,
		proposerPreferences:          preferences,
		executionConfigProvider:      &recordingExecutionConfigProvider{},
		gloasForkEpoch:               5,
		proposerPreferencesLookahead: 1,
	}

	service.publishProposerPreferences(context.Background(), 5, phase0.Root{0x01})

	require.Empty(t, preferences.duties)
}

func TestPublishProposerPreferencesRejectsStaleDependentRoot(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)

	provider := &recordingProposerDutiesProvider{
		duties:   []*apiv1.ProposerDuty{{Slot: 160, ValidatorIndex: 3}},
		metadata: map[string]any{"dependent_root": phase0.Root{0x02}},
	}
	preferences := &recordingProposerPreferences{}
	service := &Service{
		chainTimeService:             &recordingChainTime{currentEpoch: 4, slotsPerEpoch: 32},
		proposerDutiesProvider:       provider,
		proposerDutiesV2Provider:     provider,
		validatingAccountsProvider:   &proposerPreferencesAccountsProvider{accounts: accounts},
		executionConfigProvider:      &recordingExecutionConfigProvider{config: &beaconblockproposer.ProposerConfig{}},
		proposerPreferences:          preferences,
		gloasForkEpoch:               5,
		proposerPreferencesLookahead: 1,
	}

	service.publishProposerPreferences(ctx, 5, phase0.Root{0x01})

	require.Empty(t, preferences.duties)
}

func TestPublishProposerPreferencesDoesNotPublishBeforeGloas(t *testing.T) {
	provider := &recordingProposerDutiesProvider{}
	service := &Service{
		chainTimeService:             &recordingChainTime{currentEpoch: 4, slotsPerEpoch: 32},
		proposerDutiesProvider:       provider,
		proposerDutiesV2Provider:     provider,
		proposerPreferences:          &recordingProposerPreferences{},
		executionConfigProvider:      &recordingExecutionConfigProvider{},
		gloasForkEpoch:               5,
		proposerPreferencesLookahead: 1,
	}

	service.publishProposerPreferences(context.Background(), 3, phase0.Root{0x01})

	require.Zero(t, provider.calls)
}

type recordingProposerDutiesProvider struct {
	calls    int
	v1Calls  int
	v2Calls  int
	duties   []*apiv1.ProposerDuty
	metadata map[string]any
	epoch    phase0.Epoch
}

func (p *recordingProposerDutiesProvider) ProposerDuties(_ context.Context, _ *api.ProposerDutiesOpts) (*api.Response[[]*apiv1.ProposerDuty], error) {
	p.calls++
	p.v1Calls++
	return &api.Response[[]*apiv1.ProposerDuty]{Data: p.duties, Metadata: p.metadata}, nil
}

func (p *recordingProposerDutiesProvider) ProposerDutiesV2(_ context.Context, opts *api.ProposerDutiesOpts) (*api.Response[[]*apiv1.ProposerDuty], error) {
	p.calls++
	p.v2Calls++
	p.epoch = opts.Epoch
	return &api.Response[[]*apiv1.ProposerDuty]{Data: p.duties, Metadata: p.metadata}, nil
}

type headEventProposerDutiesProvider struct {
	responses map[phase0.Epoch]*api.Response[[]*apiv1.ProposerDuty]
	epochs    chan phase0.Epoch
}

func (p *headEventProposerDutiesProvider) ProposerDuties(_ context.Context, opts *api.ProposerDutiesOpts) (*api.Response[[]*apiv1.ProposerDuty], error) {
	return p.response(opts)
}

func (p *headEventProposerDutiesProvider) ProposerDutiesV2(_ context.Context, opts *api.ProposerDutiesOpts) (*api.Response[[]*apiv1.ProposerDuty], error) {
	return p.response(opts)
}

func (p *headEventProposerDutiesProvider) response(opts *api.ProposerDutiesOpts) (*api.Response[[]*apiv1.ProposerDuty], error) {
	response := p.responses[opts.Epoch]
	p.epochs <- opts.Epoch

	return response, nil
}

type headEventProposerPreferences struct {
	duties      chan *proposerpreferences.Duty
	invalidated chan slotRange
}

func (p *headEventProposerPreferences) UpdateDependentRoot(fromSlot phase0.Slot, toSlot phase0.Slot, root phase0.Root) {
	if p.invalidated != nil {
		p.invalidated <- slotRange{from: fromSlot, to: toSlot, root: root}
	}
}

func (*headEventProposerPreferences) Prune(phase0.Slot) {}

func (p *headEventProposerPreferences) Publish(_ context.Context, duty *proposerpreferences.Duty) error {
	p.duties <- duty

	return nil
}

type slotRange struct {
	from phase0.Slot
	to   phase0.Slot
	root phase0.Root
}

func receiveInvalidatedSlotRange(t *testing.T, invalidated <-chan slotRange) slotRange {
	t.Helper()
	select {
	case slots := <-invalidated:
		return slots
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proposer preferences invalidation")
		return slotRange{}
	}
}

func receiveProposerPreferencesEpoch(t *testing.T, epochs <-chan phase0.Epoch) phase0.Epoch {
	t.Helper()
	select {
	case epoch := <-epochs:
		return epoch
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proposer preferences duty epoch")
		return 0
	}
}

func receiveProposerPreferencesDuty(t *testing.T, duties <-chan *proposerpreferences.Duty) *proposerpreferences.Duty {
	t.Helper()
	select {
	case duty := <-duties:
		return duty
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proposer preferences duty")
		return nil
	}
}

func assertNoProposerPreferencesDuty(t *testing.T, duties <-chan *proposerpreferences.Duty) {
	t.Helper()
	select {
	case duty := <-duties:
		t.Fatalf("unexpected proposer preferences duty: %#v", duty)
	default:
	}
}

func waitForProposerPreferencesPublication(t *testing.T, service *Service) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		service.proposerPreferencesPublicationMutex.Lock()
		running := service.proposerPreferencesPublicationRunning
		service.proposerPreferencesPublicationMutex.Unlock()
		if !running {
			return
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for proposer preferences publication")
		case <-time.After(time.Millisecond):
		}
	}
}

type proposerPreferencesAccountsProvider struct {
	accounts map[phase0.ValidatorIndex]e2wtypes.Account
}

func (p *proposerPreferencesAccountsProvider) ValidatingAccountsForEpoch(_ context.Context, _ phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return p.accounts, nil
}

func (p *proposerPreferencesAccountsProvider) ValidatingAccountsForEpochByIndex(_ context.Context, _ phase0.Epoch, _ []phase0.ValidatorIndex) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return p.accounts, nil
}

func (*proposerPreferencesAccountsProvider) SyncCommitteeAccountsForEpoch(context.Context, phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return nil, nil
}

func (*proposerPreferencesAccountsProvider) SyncCommitteeAccountsForEpochByIndex(context.Context, phase0.Epoch, []phase0.ValidatorIndex) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return nil, nil
}

type recordingExecutionConfigProvider struct {
	config *beaconblockproposer.ProposerConfig
}

func (p *recordingExecutionConfigProvider) ProposerConfig(context.Context, e2wtypes.Account, phase0.BLSPubKey) (*beaconblockproposer.ProposerConfig, error) {
	return p.config, nil
}

type recordingProposerPreferences struct {
	duties      []*proposerpreferences.Duty
	prunedSlots []phase0.Slot
}

func (*recordingProposerPreferences) UpdateDependentRoot(phase0.Slot, phase0.Slot, phase0.Root) {}

func (p *recordingProposerPreferences) Prune(slot phase0.Slot) {
	p.prunedSlots = append(p.prunedSlots, slot)
}

func (p *recordingProposerPreferences) Publish(_ context.Context, duty *proposerpreferences.Duty) error {
	p.duties = append(p.duties, duty)
	return nil
}
