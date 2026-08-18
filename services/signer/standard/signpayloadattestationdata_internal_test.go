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

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestSignPayloadAttestationDataUsesGenericMulti(t *testing.T) {
	ctx := context.Background()
	specProvider := &ptcSpecProvider{}
	service, err := New(ctx,
		WithLogLevel(zerolog.Disabled),
		WithMonitor(nullmetrics.New()),
		WithClientMonitor(nullmetrics.New()),
		WithSpecProvider(specProvider),
		WithDomainProvider(mock.NewDomainProvider()),
	)
	require.NoError(t, err)

	batches := make([]batchRecord, 0)
	accounts := []e2wtypes.Account{
		newMockMultiSignerAccount("one", &batches),
		newMockMultiSignerAccount("two", &batches),
	}
	data := &gloas.PayloadAttestationData{Slot: 33, PayloadPresent: true}

	sigs, err := service.SignPayloadAttestationData(ctx, accounts, data)
	require.NoError(t, err)
	require.Len(t, sigs, 2)
	require.NotEqual(t, phase0.BLSSignature{}, sigs[0])
	require.NotEqual(t, phase0.BLSSignature{}, sigs[1])
	require.Len(t, batches, 1)
}

type ptcSpecProvider struct{}

func (*ptcSpecProvider) Spec(_ context.Context, _ *api.SpecOpts) (*api.Response[map[string]any], error) {
	return &api.Response[map[string]any]{Data: map[string]any{
		"SLOTS_PER_EPOCH":            uint64(32),
		"DOMAIN_BEACON_ATTESTER":     phase0.DomainType{0x01},
		"DOMAIN_BEACON_PROPOSER":     phase0.DomainType{0x02},
		"DOMAIN_RANDAO":              phase0.DomainType{0x03},
		"DOMAIN_SELECTION_PROOF":     phase0.DomainType{0x04},
		"DOMAIN_AGGREGATE_AND_PROOF": phase0.DomainType{0x05},
		"DOMAIN_PTC_ATTESTER":        phase0.DomainType{0x0c},
	}}, nil
}
