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

package staticdelay

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/OffchainLabs/go-bitfield"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	beaconblockheader "github.com/attestantio/vouch/strategies/beaconblockheader/first"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

var registerMetricsOnce sync.Once

func ensureMetricsRegistered(t *testing.T) {
	t.Helper()
	registerMetricsOnce.Do(func() {
		require.NoError(t, registerPrometheusMetrics(context.Background()))
	})
}

func TestProposerGaugeTracksIndependentTransitions(t *testing.T) {
	ensureMetricsRegistered(t)
	s, err := newStaticDelayService(t, fixedSpecProvider{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
	})
	require.NoError(t, err)
	require.Equal(t, float64(1), proposerGauge(t))

	s.disableProposer(context.Background())
	s.enableAttester(context.Background())
	require.Equal(t, float64(0), proposerGauge(t))

	s.enableProposer(context.Background())
	s.enableProposer(context.Background())
	s.disableAttester(context.Background())
	require.Equal(t, float64(1), proposerGauge(t))

	s.disableProposer(context.Background())
	require.Equal(t, float64(0), proposerGauge(t))
}

func proposerGauge(t *testing.T) float64 {
	return activeGauge(t, "proposer")
}

func activeGauge(t *testing.T, operation string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != "vouch_multiinstance_active" {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "operation" && label.GetValue() == operation {
					return metric.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatal("active gauge not found")
	return 0
}

func TestPrimaryDutiesRestoreActiveGaugesAfterFailure(t *testing.T) {
	ensureMetricsRegistered(t)
	s, err := newStaticDelayService(t, fixedSpecProvider{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
	})
	require.NoError(t, err)
	s.attesterDelay = 0
	duty, err := attester.NewDuty(context.Background(), 1, 1,
		[]phase0.ValidatorIndex{1}, []phase0.CommitteeIndex{0}, []uint64{0},
		map[phase0.CommitteeIndex]uint64{0: 1},
	)
	require.NoError(t, err)
	proposerDuty := beaconblockproposer.NewDuty(1, 1)
	s.OnAttestationFailure(context.Background(), duty)
	s.OnProposalFailure(context.Background(), proposerDuty)
	require.Zero(t, activeGauge(t, "attester"))
	require.Zero(t, activeGauge(t, "proposer"))

	require.True(t, s.ShouldAttest(context.Background(), duty))
	require.True(t, s.ShouldPropose(context.Background(), proposerDuty))
	require.Equal(t, float64(1), activeGauge(t, "attester"))
	require.Equal(t, float64(1), activeGauge(t, "proposer"))
}

func TestActiveAttesterRechecksPoolAfterPrimaryRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, err := newStaticDelayService(t, fixedSpecProvider{
			"SECONDS_PER_SLOT": 12 * time.Second,
			"SLOTS_PER_EPOCH":  uint64(32),
		})
		require.NoError(t, err)
		ensureMetricsRegistered(t)
		s.enableAttester(context.Background())
		s.attestationPoolProvider = &sequenceAttestationPool{responses: [][]*spec.VersionedAttestation{
			recoveredAttestation(),
		}}
		duty, err := attester.NewDuty(context.Background(), 0, 1,
			[]phase0.ValidatorIndex{1}, []phase0.CommitteeIndex{0}, []uint64{0},
			map[phase0.CommitteeIndex]uint64{0: 1},
		)
		require.NoError(t, err)

		require.False(t, s.ShouldAttest(context.Background(), duty))
		require.Zero(t, activeGauge(t, "attester"))
	})
}

func TestAttesterActivationDoesNotBypassHealthyProposer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, err := newStaticDelayService(t, fixedSpecProvider{
			"SECONDS_PER_SLOT": 12 * time.Second,
			"SLOTS_PER_EPOCH":  uint64(32),
		})
		require.NoError(t, err)
		ensureMetricsRegistered(t)
		s.proposerDelay = time.Second
		s.beaconBlockHeadersProvider = &headerSequenceProvider{outcomes: []headerOutcome{
			{response: &api.Response[*apiv1.BeaconBlockHeader]{Data: &apiv1.BeaconBlockHeader{}}},
		}}
		duty, err := attester.NewDuty(context.Background(), 1, 1,
			[]phase0.ValidatorIndex{1}, []phase0.CommitteeIndex{0}, []uint64{0},
			map[phase0.CommitteeIndex]uint64{0: 1},
		)
		require.NoError(t, err)

		require.True(t, s.ShouldAttest(context.Background(), duty))
		require.False(t, s.ShouldPropose(context.Background(), beaconblockproposer.NewDuty(1, 1)))
		require.Zero(t, activeGauge(t, "proposer"))
	})
}

func TestProposerTakesOverThenRelinquishesAfterPrimaryRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, err := newStaticDelayService(t, fixedSpecProvider{
			"SECONDS_PER_SLOT": 12 * time.Second,
			"SLOTS_PER_EPOCH":  uint64(32),
		})
		require.NoError(t, err)
		ensureMetricsRegistered(t)
		s.proposerDelay = time.Second
		s.disableProposer(context.Background())
		s.beaconBlockHeadersProvider = &headerSequenceProvider{outcomes: []headerOutcome{
			{err: &api.Error{StatusCode: 404}},
			{response: &api.Response[*apiv1.BeaconBlockHeader]{Data: &apiv1.BeaconBlockHeader{}}},
		}}

		require.True(t, s.ShouldPropose(context.Background(), beaconblockproposer.NewDuty(1, 1)))
		require.Equal(t, float64(1), activeGauge(t, "proposer"))
		require.False(t, s.ShouldPropose(context.Background(), beaconblockproposer.NewDuty(2, 1)))
		require.Zero(t, activeGauge(t, "proposer"))
	})
}

func TestPrimaryProposerDoesNotWaitForHeader(t *testing.T) {
	s, err := newStaticDelayService(t, fixedSpecProvider{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
	})
	require.NoError(t, err)
	provider := &headerSequenceProvider{outcomes: []headerOutcome{{err: errors.New("unexpected header lookup")}}}
	s.beaconBlockHeadersProvider = provider

	require.True(t, s.ShouldPropose(context.Background(), beaconblockproposer.NewDuty(1, 1)))
	require.Zero(t, provider.calls)
}

func TestPrimaryAttesterDoesNotWaitForPool(t *testing.T) {
	s, err := newStaticDelayService(t, fixedSpecProvider{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
	})
	require.NoError(t, err)
	s.attesterDelay = 0
	provider := &countingAttestationPool{}
	s.attestationPoolProvider = provider
	duty, err := attester.NewDuty(context.Background(), 1, 1,
		[]phase0.ValidatorIndex{1}, []phase0.CommitteeIndex{0}, []uint64{0},
		map[phase0.CommitteeIndex]uint64{0: 1},
	)
	require.NoError(t, err)

	require.True(t, s.ShouldAttest(context.Background(), duty))
	require.Zero(t, provider.calls)
}

type countingAttestationPool struct {
	calls int
}

func (p *countingAttestationPool) AttestationPool(context.Context, *api.AttestationPoolOpts) (*api.Response[[]*spec.VersionedAttestation], error) {
	p.calls++
	return nil, nil
}

func (p *headerSequenceProvider) BeaconBlockHeader(context.Context, *api.BeaconBlockHeaderOpts) (*api.Response[*apiv1.BeaconBlockHeader], error) {
	outcome := p.outcomes[p.calls]
	p.calls++

	return outcome.response, outcome.err
}

type headerSequenceProvider struct {
	outcomes []headerOutcome
	calls    int
}

type headerOutcome struct {
	response *api.Response[*apiv1.BeaconBlockHeader]
	err      error
}

func TestProposerActivatesOnlyOnDefinitiveHeaderAbsence(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		activate bool
	}{
		{name: "DefinitiveAbsence", err: beaconblockheader.ErrBeaconBlockHeaderNotFound, activate: true},
		{name: "ProviderNotFound", err: &api.Error{StatusCode: 404}, activate: true},
		{name: "WrappedProviderNotFound", err: errors.Join(errors.New("lookup"), &api.Error{StatusCode: 404}), activate: true},
		{name: "ProviderFailure", err: errors.New("connection refused"), activate: false},
		{name: "ServerError", err: &api.Error{StatusCode: 503}, activate: false},
		{name: "Timeout", err: beaconblockheader.ErrBeaconBlockHeaderTimeout, activate: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, err := newStaticDelayService(t, fixedSpecProvider{
					"SECONDS_PER_SLOT": 12 * time.Second,
					"SLOTS_PER_EPOCH":  uint64(32),
				})
				require.NoError(t, err)
				ensureMetricsRegistered(t)
				s.proposerDelay = time.Second
				s.enableProposer(context.Background())
				s.beaconBlockHeadersProvider = &headerSequenceProvider{outcomes: []headerOutcome{{err: test.err}}}

				require.Equal(t, test.activate, s.ShouldPropose(context.Background(), beaconblockproposer.NewDuty(1, 1)))
				if test.activate {
					require.Equal(t, float64(1), activeGauge(t, "proposer"))
				} else {
					require.Zero(t, activeGauge(t, "proposer"))
				}
			})
		})
	}
}

func TestAttesterReevaluatesAfterSuccessfulTakeover(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, err := newStaticDelayService(t, fixedSpecProvider{
			"SECONDS_PER_SLOT": 12 * time.Second,
			"SLOTS_PER_EPOCH":  uint64(32),
		})
		require.NoError(t, err)
		ensureMetricsRegistered(t)
		s.attestationPoolProvider = &sequenceAttestationPool{responses: [][]*spec.VersionedAttestation{
			{},
			recoveredAttestation(),
		}}
		firstDuty, err := attester.NewDuty(context.Background(), 0, 1,
			[]phase0.ValidatorIndex{1}, []phase0.CommitteeIndex{0}, []uint64{0},
			map[phase0.CommitteeIndex]uint64{0: 1},
		)
		require.NoError(t, err)
		secondDuty, err := attester.NewDuty(context.Background(), 1, 1,
			[]phase0.ValidatorIndex{1}, []phase0.CommitteeIndex{0}, []uint64{0},
			map[phase0.CommitteeIndex]uint64{0: 1},
		)
		require.NoError(t, err)

		require.True(t, s.ShouldAttest(context.Background(), firstDuty))
		require.Equal(t, float64(1), activeGauge(t, "attester"))
		require.False(t, s.ShouldAttest(context.Background(), secondDuty))
		require.Zero(t, activeGauge(t, "attester"))
	})
}

type sequenceAttestationPool struct {
	responses [][]*spec.VersionedAttestation
	calls     int
}

func (p *sequenceAttestationPool) AttestationPool(_ context.Context, _ *api.AttestationPoolOpts) (*api.Response[[]*spec.VersionedAttestation], error) {
	response := p.responses[p.calls]
	p.calls++
	return &api.Response[[]*spec.VersionedAttestation]{Data: response}, nil
}

func recoveredAttestation() []*spec.VersionedAttestation {
	bits := bitfield.NewBitlist(1)
	bits.SetBitAt(0, true)
	return []*spec.VersionedAttestation{{
		Version: spec.DataVersionPhase0,
		Phase0: &phase0.Attestation{
			AggregationBits: bits,
			Data:            &phase0.AttestationData{Index: 0},
		},
	}}
}
