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
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/attester/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestAttestGloasPreservesAttestationIndex(t *testing.T) {
	ctx := context.Background()
	chainTime := &attesterTestChainTime{
		hardForkEpochs: map[string]phase0.Epoch{
			"GLOAS_FORK_EPOCH":   15,
			"ELECTRA_FORK_EPOCH": 0,
			"FULU_FORK_EPOCH":    10,
		},
		slotsPerEpoch: 1,
	}
	accounts := mockAccountProvider()
	accounts.AddAccount(1, testAccount{})
	signer := &capturingBeaconAttestationsSigner{signatures: []phase0.BLSSignature{{0x01}}}
	submitter := &capturingAttestationsSubmitter{}

	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithProcessConcurrency(1),
		standard.WithChainTime(chainTime),
		standard.WithSpecProvider(testSpecProvider{}),
		standard.WithAttestationDataProvider(testAttestationDataProvider{index: 1}),
		standard.WithAttestationsSubmitter(submitter),
		standard.WithValidatingAccountsProvider(accounts),
		standard.WithBeaconAttestationsSigner(signer),
	)
	require.NoError(t, err)

	duty, err := attester.NewDuty(ctx,
		15,
		1,
		[]phase0.ValidatorIndex{1},
		[]phase0.CommitteeIndex{0},
		[]uint64{0},
		map[phase0.CommitteeIndex]uint64{0: 1},
	)
	require.NoError(t, err)

	attestations, err := service.Attest(ctx, duty)
	require.NoError(t, err)
	require.Len(t, attestations, 1)
	require.Len(t, signer.committeeIndices, 1)
	require.Equal(t, phase0.CommitteeIndex(1), signer.committeeIndices[0])
	require.NotNil(t, submitter.opts)
	require.Len(t, submitter.opts.Attestations, 1)
	require.Equal(t, spec.DataVersionGloas, submitter.opts.Attestations[0].Version)
	require.NotNil(t, submitter.opts.Attestations[0].Gloas)
	committeeIndex, err := submitter.opts.Attestations[0].CommitteeIndex()
	require.NoError(t, err)
	require.Equal(t, phase0.CommitteeIndex(0), committeeIndex)
	require.Equal(t, phase0.CommitteeIndex(1), submitter.opts.Attestations[0].Gloas.Data.Index)
	require.Equal(t, signer.committeeIndices[0], submitter.opts.Attestations[0].Gloas.Data.Index)
}

func TestAttestRejectsInvalidGloasAttestationIndex(t *testing.T) {
	ctx := context.Background()
	chainTime := &attesterTestChainTime{
		hardForkEpochs: map[string]phase0.Epoch{
			"GLOAS_FORK_EPOCH":   15,
			"ELECTRA_FORK_EPOCH": 0,
			"FULU_FORK_EPOCH":    10,
		},
		slotsPerEpoch: 1,
	}
	accounts := mockAccountProvider()
	accounts.AddAccount(1, testAccount{})
	signer := &capturingBeaconAttestationsSigner{signatures: []phase0.BLSSignature{{0x01}}}
	submitter := &capturingAttestationsSubmitter{}

	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithProcessConcurrency(1),
		standard.WithChainTime(chainTime),
		standard.WithSpecProvider(testSpecProvider{}),
		standard.WithAttestationDataProvider(testAttestationDataProvider{index: 2}),
		standard.WithAttestationsSubmitter(submitter),
		standard.WithValidatingAccountsProvider(accounts),
		standard.WithBeaconAttestationsSigner(signer),
	)
	require.NoError(t, err)

	duty, err := attester.NewDuty(ctx,
		15,
		1,
		[]phase0.ValidatorIndex{1},
		[]phase0.CommitteeIndex{0},
		[]uint64{0},
		map[phase0.CommitteeIndex]uint64{0: 1},
	)
	require.NoError(t, err)

	_, err = service.Attest(ctx, duty)
	require.EqualError(t, err, "attestation request for slot 15 returned invalid Gloas index 2")
	require.Equal(t, 0, signer.calls)
	require.Equal(t, 0, submitter.calls)
}

func TestAttestElectraAndFuluKeepZeroAttestationIndex(t *testing.T) {
	tests := []struct {
		name    string
		slot    phase0.Slot
		version spec.DataVersion
	}{
		{name: "Electra", slot: 1, version: spec.DataVersionElectra},
		{name: "Fulu", slot: 11, version: spec.DataVersionFulu},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			chainTime := &attesterTestChainTime{
				hardForkEpochs: map[string]phase0.Epoch{
					"GLOAS_FORK_EPOCH":   15,
					"ELECTRA_FORK_EPOCH": 0,
					"FULU_FORK_EPOCH":    10,
				},
				slotsPerEpoch: 1,
			}
			accounts := mockAccountProvider()
			accounts.AddAccount(1, testAccount{})
			signer := &capturingBeaconAttestationsSigner{signatures: []phase0.BLSSignature{{0x01}}}
			submitter := &capturingAttestationsSubmitter{}
			service, err := standard.New(ctx,
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithProcessConcurrency(1),
				standard.WithChainTime(chainTime),
				standard.WithSpecProvider(testSpecProvider{}),
				standard.WithAttestationDataProvider(testAttestationDataProvider{index: 1}),
				standard.WithAttestationsSubmitter(submitter),
				standard.WithValidatingAccountsProvider(accounts),
				standard.WithBeaconAttestationsSigner(signer),
			)
			require.NoError(t, err)

			duty, err := attester.NewDuty(ctx,
				test.slot,
				1,
				[]phase0.ValidatorIndex{1},
				[]phase0.CommitteeIndex{1},
				[]uint64{0},
				map[phase0.CommitteeIndex]uint64{1: 1},
			)
			require.NoError(t, err)

			_, err = service.Attest(ctx, duty)
			require.NoError(t, err)
			require.Equal(t, []phase0.CommitteeIndex{0}, signer.committeeIndices)
			require.NotNil(t, submitter.opts)
			require.Len(t, submitter.opts.Attestations, 1)
			require.Equal(t, test.version, submitter.opts.Attestations[0].Version)
			data, err := submitter.opts.Attestations[0].Data()
			require.NoError(t, err)
			require.Equal(t, phase0.CommitteeIndex(0), data.Index)
		})
	}
}

func mockAccountProvider() *mockaccountmanager.ValidatingAccountsProvider {
	return mockaccountmanager.NewValidatingAccountsProvider()
}

type testAccount struct{}

func (testAccount) ID() uuid.UUID                { return uuid.Nil }
func (testAccount) Name() string                 { return "test" }
func (testAccount) PublicKey() e2types.PublicKey { return testPublicKey{} }

var _ e2wtypes.Account = testAccount{}

type testPublicKey struct{}

func (testPublicKey) Marshal() []byte             { return make([]byte, 48) }
func (testPublicKey) Aggregate(e2types.PublicKey) {}
func (key testPublicKey) Copy() e2types.PublicKey { return key }

type testSpecProvider struct{}

func (testSpecProvider) Spec(context.Context, *api.SpecOpts) (*api.Response[map[string]any], error) {
	return &api.Response[map[string]any]{Data: map[string]any{"SLOTS_PER_EPOCH": uint64(1)}}, nil
}

type testAttestationDataProvider struct {
	index phase0.CommitteeIndex
}

func (provider testAttestationDataProvider) AttestationData(_ context.Context, opts *api.AttestationDataOpts) (*api.Response[*phase0.AttestationData], error) {
	return &api.Response[*phase0.AttestationData]{Data: &phase0.AttestationData{
		Slot:  opts.Slot,
		Index: provider.index,
		Source: &phase0.Checkpoint{
			Epoch: phase0.Epoch(opts.Slot - 1),
		},
		Target: &phase0.Checkpoint{
			Epoch: phase0.Epoch(opts.Slot),
		},
	}}, nil
}

type capturingBeaconAttestationsSigner struct {
	calls            int
	committeeIndices []phase0.CommitteeIndex
	signatures       []phase0.BLSSignature
}

func (s *capturingBeaconAttestationsSigner) SignBeaconAttestations(_ context.Context, _ []e2wtypes.Account, _ phase0.Slot, committeeIndices []phase0.CommitteeIndex, _ phase0.Root, _ phase0.Epoch, _ phase0.Root, _ phase0.Epoch, _ phase0.Root) ([]phase0.BLSSignature, error) {
	s.calls++
	s.committeeIndices = append([]phase0.CommitteeIndex(nil), committeeIndices...)
	return s.signatures, nil
}

var _ signer.BeaconAttestationsSigner = (*capturingBeaconAttestationsSigner)(nil)

type capturingAttestationsSubmitter struct {
	calls int
	opts  *api.SubmitAttestationsOpts
}

func (s *capturingAttestationsSubmitter) SubmitAttestations(_ context.Context, opts *api.SubmitAttestationsOpts) error {
	s.calls++
	s.opts = opts
	return nil
}

var _ submitter.AttestationsSubmitter = (*capturingAttestationsSubmitter)(nil)

type attesterTestChainTime struct {
	hardForkEpochs map[string]phase0.Epoch
	slotsPerEpoch  uint64
}

func (s *attesterTestChainTime) GenesisTime() time.Time { return time.Unix(0, 0) }
func (s *attesterTestChainTime) StartOfSlot(slot phase0.Slot) time.Time {
	return s.GenesisTime().Add(time.Duration(slot) * time.Second)
}
func (s *attesterTestChainTime) StartOfEpoch(epoch phase0.Epoch) time.Time {
	return s.StartOfSlot(phase0.Slot(uint64(epoch) * s.slotsPerEpoch))
}
func (s *attesterTestChainTime) CurrentSlot() phase0.Slot   { return 0 }
func (s *attesterTestChainTime) CurrentEpoch() phase0.Epoch { return 0 }
func (s *attesterTestChainTime) SlotToEpoch(slot phase0.Slot) phase0.Epoch {
	return phase0.Epoch(uint64(slot) / s.slotsPerEpoch)
}
func (s *attesterTestChainTime) FirstSlotOfEpoch(epoch phase0.Epoch) phase0.Slot {
	return phase0.Slot(uint64(epoch) * s.slotsPerEpoch)
}
func (s *attesterTestChainTime) HardForkEpoch(_ context.Context, name string) phase0.Epoch {
	return s.hardForkEpochs[name]
}

var _ interface {
	GenesisTime() time.Time
	StartOfSlot(phase0.Slot) time.Time
	StartOfEpoch(phase0.Epoch) time.Time
	CurrentSlot() phase0.Slot
	CurrentEpoch() phase0.Epoch
	SlotToEpoch(phase0.Slot) phase0.Epoch
	FirstSlotOfEpoch(phase0.Epoch) phase0.Slot
	HardForkEpoch(context.Context, string) phase0.Epoch
} = (*attesterTestChainTime)(nil)
