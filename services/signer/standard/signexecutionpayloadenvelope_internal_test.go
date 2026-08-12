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
	mockconsensusclient "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSignExecutionPayloadEnvelope(t *testing.T) {
	ctx := context.Background()
	proposalClient, err := mockconsensusclient.New(ctx)
	require.NoError(t, err)
	includePayload := true
	proposalResponse, err := proposalClient.EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot:           33,
		IncludePayload: &includePayload,
	})
	require.NoError(t, err)

	domainProvider := &recordingDomainProvider{}
	service, err := New(ctx,
		WithLogLevel(zerolog.Disabled),
		WithMonitor(nullmetrics.New()),
		WithClientMonitor(nullmetrics.New()),
		WithSpecProvider(mock.NewSpecProvider()),
		WithDomainProvider(domainProvider),
	)
	require.NoError(t, err)
	account := newMockAccount("builder")

	signature, err := service.SignExecutionPayloadEnvelope(ctx,
		account,
		33,
		proposalResponse.Data.GloasContents.ExecutionPayloadEnvelope,
	)
	require.NoError(t, err)
	require.NotEqual(t, phase0.BLSSignature{}, signature)
	require.Equal(t, 1, account.signCount)
	require.Equal(t, phase0.DomainType{0x0a}, domainProvider.domainType)
	require.Equal(t, phase0.Epoch(1), domainProvider.epoch)
}

func TestSignExecutionPayloadEnvelopeUnavailableBeforeGloas(t *testing.T) {
	ctx := context.Background()
	service, err := New(ctx,
		WithLogLevel(zerolog.Disabled),
		WithMonitor(nullmetrics.New()),
		WithClientMonitor(nullmetrics.New()),
		WithSpecProvider(&preGloasSpecProvider{}),
		WithDomainProvider(&recordingDomainProvider{}),
	)
	require.NoError(t, err)
	account := newMockAccount("legacy")

	signature, err := service.SignBeaconBlockProposal(ctx,
		account,
		32,
		0,
		phase0.Root{},
		phase0.Root{},
		phase0.Root{},
	)
	require.NoError(t, err)
	require.NotEqual(t, phase0.BLSSignature{}, signature)

	_, err = service.SignExecutionPayloadEnvelope(ctx, account, 32, &gloas.ExecutionPayloadEnvelope{})
	require.EqualError(t, err, "DOMAIN_BEACON_BUILDER unavailable in beacon node spec; cannot sign execution payload envelope")
	require.Equal(t, 1, account.signCount)
}

func TestNewWarnsWhenBeaconBuilderDomainUnavailable(t *testing.T) {
	capture := logger.NewLogCapture()

	_, err := New(context.Background(),
		WithLogLevel(zerolog.WarnLevel),
		WithMonitor(nullmetrics.New()),
		WithClientMonitor(nullmetrics.New()),
		WithSpecProvider(&preGloasSpecProvider{}),
		WithDomainProvider(&recordingDomainProvider{}),
	)
	require.NoError(t, err)
	capture.AssertHasEntry(t, "DOMAIN_BEACON_BUILDER unavailable in spec; execution payload envelope signing unavailable")
}

type preGloasSpecProvider struct{}

func (*preGloasSpecProvider) Spec(_ context.Context, _ *api.SpecOpts) (*api.Response[map[string]any], error) {
	return &api.Response[map[string]any]{
		Data: map[string]any{
			"SLOTS_PER_EPOCH":            uint64(32),
			"DOMAIN_BEACON_ATTESTER":     phase0.DomainType{0x01},
			"DOMAIN_BEACON_PROPOSER":     phase0.DomainType{0x02},
			"DOMAIN_RANDAO":              phase0.DomainType{0x03},
			"DOMAIN_SELECTION_PROOF":     phase0.DomainType{0x04},
			"DOMAIN_AGGREGATE_AND_PROOF": phase0.DomainType{0x05},
		},
	}, nil
}

type recordingDomainProvider struct {
	domainType phase0.DomainType
	epoch      phase0.Epoch
}

func (p *recordingDomainProvider) Domain(_ context.Context, domainType phase0.DomainType, epoch phase0.Epoch) (phase0.Domain, error) {
	p.domainType = domainType
	p.epoch = epoch
	var domain phase0.Domain
	copy(domain[:], domainType[:])
	return domain, nil
}

func (*recordingDomainProvider) GenesisDomain(context.Context, phase0.DomainType) (phase0.Domain, error) {
	return phase0.Domain{}, nil
}
