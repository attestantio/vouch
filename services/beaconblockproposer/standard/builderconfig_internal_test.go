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
	"errors"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/testutil"
	"github.com/stretchr/testify/require"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestBuilderConfigRejectsNilBuilder(t *testing.T) {
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service := &Service{
		executionConfigProvider: &builderConfigProvider{config: &beaconblockproposer.ProposerConfig{
			EPBSBuilderConfig: &beaconblockproposer.EPBSBuilderConfig{
				BuilderBoostFactor: 100,
				Builders:           []*beaconblockproposer.EPBSBuilder{nil},
			},
		}},
		builderRequestAuthSigner: builderConfigSigner{},
	}

	duty := beaconblockproposer.NewDuty(1, 0)
	duty.SetAccount(accounts[1])
	config, _, err := service.builderConfig(context.Background(), duty)
	require.Nil(t, config)
	require.EqualError(t, err, "direct builder 0 is missing")
}

type builderConfigProvider struct {
	config *beaconblockproposer.ProposerConfig
}

func (p *builderConfigProvider) ProposerConfig(context.Context, e2wtypes.Account, phase0.BLSPubKey) (*beaconblockproposer.ProposerConfig, error) {
	return p.config, nil
}

func TestBuilderConfigRequiresSignerForDirectBuilders(t *testing.T) {
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service := &Service{executionConfigProvider: &builderConfigProvider{config: &beaconblockproposer.ProposerConfig{
		EPBSBuilderConfig: &beaconblockproposer.EPBSBuilderConfig{
			BuilderBoostFactor: 100,
			Builders:           []*beaconblockproposer.EPBSBuilder{{URL: "https://builder.example", AuthData: []byte{0x12}}},
		},
	}}}
	duty := beaconblockproposer.NewDuty(1, 0)
	duty.SetAccount(accounts[1])

	config, _, err := service.builderConfig(context.Background(), duty)
	require.Nil(t, config)
	require.EqualError(t, err, "no builder request authorization signer available")
}

func TestBuilderConfigBindsAuthToEachDutySlot(t *testing.T) {
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	signer := &recordingBuilderConfigSigner{}
	service := &Service{
		executionConfigProvider: &builderConfigProvider{config: &beaconblockproposer.ProposerConfig{
			EPBSBuilderConfig: &beaconblockproposer.EPBSBuilderConfig{
				BuilderBoostFactor: 100,
				Builders:           []*beaconblockproposer.EPBSBuilder{{URL: "https://builder.example", AuthData: []byte{0x12}}},
			},
		}},
		builderRequestAuthSigner: signer,
	}

	for _, slot := range []phase0.Slot{1, 2} {
		duty := beaconblockproposer.NewDuty(slot, 0)
		duty.SetAccount(accounts[1])
		config, _, err := service.builderConfig(context.Background(), duty)
		require.NoError(t, err)
		require.Equal(t, slot, config.Builders[0].Auth.Message.Slot)
	}
	require.Equal(t, []phase0.Slot{1, 2}, signer.slots)
}

func TestBuilderConfigRedactsSigningFailure(t *testing.T) {
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	sensitive := "private-auth-value"
	service := &Service{
		executionConfigProvider: &builderConfigProvider{config: &beaconblockproposer.ProposerConfig{
			EPBSBuilderConfig: &beaconblockproposer.EPBSBuilderConfig{
				BuilderBoostFactor: 100,
				Builders: []*beaconblockproposer.EPBSBuilder{{
					URL:      "https://builder.example",
					AuthData: []byte(sensitive),
				}},
			},
		}},
		builderRequestAuthSigner: builderConfigSigner{err: errors.New(sensitive)},
	}
	duty := beaconblockproposer.NewDuty(1, 0)
	duty.SetAccount(accounts[1])

	config, _, err := service.builderConfig(context.Background(), duty)
	require.Nil(t, config)
	require.EqualError(t, err, "failed to sign direct-builder request authorization")
	require.NotContains(t, err.Error(), sensitive)
}

type builderConfigSigner struct {
	err error
}

func (s builderConfigSigner) SignBuilderRequestAuth(context.Context, e2wtypes.Account, *gloas.BuilderRequestAuth) (phase0.BLSSignature, error) {
	return phase0.BLSSignature{}, s.err
}

type recordingBuilderConfigSigner struct {
	slots []phase0.Slot
}

func (s *recordingBuilderConfigSigner) SignBuilderRequestAuth(_ context.Context, _ e2wtypes.Account, auth *gloas.BuilderRequestAuth) (phase0.BLSSignature, error) {
	s.slots = append(s.slots, auth.Slot)
	return phase0.BLSSignature{}, nil
}
