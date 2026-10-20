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
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestSignBuilderRequestAuthRejectsNilAuth(t *testing.T) {
	signature, err := (&Service{}).SignBuilderRequestAuth(context.Background(), &recordingBuilderAuthAccount{}, nil)
	require.Equal(t, phase0.BLSSignature{}, signature)
	require.EqualError(t, err, "no builder request authorization supplied")
}

func TestSignBuilderRequestAuthUsesGenericSigner(t *testing.T) {
	tests := []struct {
		name               string
		genesisForkVersion *phase0.Version
		domain             string
		err                string
	}{
		{
			name:               "Mainnet",
			genesisForkVersion: &phase0.Version{0x00, 0x00, 0x00, 0x00},
			domain:             "0b000001f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9",
		},
		{
			name:               "Hoodi",
			genesisForkVersion: &phase0.Version{0x10, 0x00, 0x09, 0x10},
			domain:             "0b000001719103511efa4f1362ff2a50996cccf329cc84cb410c5e5c7d351d03",
		},
		{
			name: "GenesisForkVersionMissing",
			err:  "no builder request authorization domain available; cannot sign",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			spec := map[string]any{
				"SLOTS_PER_EPOCH":            uint64(32),
				"DOMAIN_BEACON_ATTESTER":     phase0.DomainType{0x01},
				"DOMAIN_BEACON_PROPOSER":     phase0.DomainType{0x02},
				"DOMAIN_RANDAO":              phase0.DomainType{0x03},
				"DOMAIN_SELECTION_PROOF":     phase0.DomainType{0x04},
				"DOMAIN_AGGREGATE_AND_PROOF": phase0.DomainType{0x05},
			}
			if test.genesisForkVersion != nil {
				spec["GENESIS_FORK_VERSION"] = *test.genesisForkVersion
			}
			service, err := New(ctx,
				WithLogLevel(zerolog.Disabled),
				WithMonitor(nullmetrics.New()),
				WithClientMonitor(nullmetrics.New()),
				WithSpecProvider(&builderAuthSpecProvider{spec: spec}),
				WithDomainProvider(mock.NewDomainProvider()),
			)
			require.NoError(t, err)
			auth := &gloas.BuilderRequestAuth{Data: []byte{0x12, 0x34}, Slot: 42}
			root, err := auth.HashTreeRoot()
			require.NoError(t, err)
			account := &recordingBuilderAuthAccount{}

			signature, err := service.SignBuilderRequestAuth(ctx, account, auth)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				require.Zero(t, account.calls)

				return
			}
			require.NoError(t, err)
			require.Equal(t, phase0.BLSSignature{0x99}, signature)
			require.Equal(t, root[:], account.data)
			require.Equal(t, test.domain, hex.EncodeToString(account.domain))
			require.Equal(t, 1, account.calls)
		})
	}
}

type builderAuthSpecProvider struct {
	spec map[string]any
}

func (p *builderAuthSpecProvider) Spec(context.Context, *api.SpecOpts) (*api.Response[map[string]any], error) {
	return &api.Response[map[string]any]{Data: p.spec}, nil
}

type recordingBuilderAuthAccount struct {
	data   []byte
	domain []byte
	calls  int
}

func (*recordingBuilderAuthAccount) ID() uuid.UUID { return uuid.Nil }
func (*recordingBuilderAuthAccount) Name() string  { return "builder-auth" }
func (*recordingBuilderAuthAccount) PublicKey() e2types.PublicKey {
	return nil
}
func (a *recordingBuilderAuthAccount) SignGeneric(_ context.Context, data []byte, domain []byte) (e2types.Signature, error) {
	a.calls++
	a.data = append([]byte(nil), data...)
	a.domain = append([]byte(nil), domain...)

	return builderAuthSignature{}, nil
}
func (*recordingBuilderAuthAccount) SignBeaconProposal(context.Context, uint64, uint64, []byte, []byte, []byte, []byte) (e2types.Signature, error) {
	return nil, nil
}
func (*recordingBuilderAuthAccount) SignBeaconAttestation(context.Context, uint64, uint64, []byte, uint64, []byte, uint64, []byte, []byte) (e2types.Signature, error) {
	return nil, nil
}

var _ e2wtypes.AccountProtectingSigner = (*recordingBuilderAuthAccount)(nil)

type builderAuthSignature struct{}

func (builderAuthSignature) Verify([]byte, e2types.PublicKey) bool                  { return false }
func (builderAuthSignature) VerifyAggregate([][]byte, []e2types.PublicKey) bool     { return false }
func (builderAuthSignature) VerifyAggregateCommon([]byte, []e2types.PublicKey) bool { return false }
func (builderAuthSignature) Marshal() []byte                                        { return append([]byte{0x99}, make([]byte, 95)...) }
