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
		validatingAccountsProvider:   &proposerPreferencesAccountsProvider{accounts: accounts},
		executionConfigProvider:      &recordingExecutionConfigProvider{config: &beaconblockproposer.ProposerConfig{FeeRecipient: bellatrix.ExecutionAddress{0x02}, GasLimit: 30_000_000}},
		proposerPreferences:          preferences,
		gloasForkEpoch:               5,
		proposerPreferencesLookahead: 1,
	}

	service.publishProposerPreferences(ctx, 4, phase0.Root{0x01})

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

func TestPublishProposerPreferencesRejectsDutiesWithoutDependentRoot(t *testing.T) {
	provider := &recordingProposerDutiesProvider{duties: []*apiv1.ProposerDuty{{Slot: 160, ValidatorIndex: 3}}}
	preferences := &recordingProposerPreferences{}
	service := &Service{
		chainTimeService:             &recordingChainTime{currentEpoch: 4, slotsPerEpoch: 32},
		proposerDutiesProvider:       provider,
		proposerPreferences:          preferences,
		executionConfigProvider:      &recordingExecutionConfigProvider{},
		gloasForkEpoch:               5,
		proposerPreferencesLookahead: 1,
	}

	service.publishProposerPreferences(context.Background(), 4, phase0.Root{0x01})

	require.Empty(t, preferences.duties)
}

func TestPublishProposerPreferencesDoesNotPublishBeforeGloas(t *testing.T) {
	provider := &recordingProposerDutiesProvider{}
	service := &Service{
		chainTimeService:             &recordingChainTime{currentEpoch: 4, slotsPerEpoch: 32},
		proposerDutiesProvider:       provider,
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
	duties   []*apiv1.ProposerDuty
	metadata map[string]any
	epoch    phase0.Epoch
}

func (p *recordingProposerDutiesProvider) ProposerDuties(_ context.Context, opts *api.ProposerDutiesOpts) (*api.Response[[]*apiv1.ProposerDuty], error) {
	p.calls++
	p.epoch = opts.Epoch
	return &api.Response[[]*apiv1.ProposerDuty]{Data: p.duties, Metadata: p.metadata}, nil
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
	duties []*proposerpreferences.Duty
}

func (p *recordingProposerPreferences) Publish(_ context.Context, duty *proposerpreferences.Duty) error {
	p.duties = append(p.duties, duty)
	return nil
}
