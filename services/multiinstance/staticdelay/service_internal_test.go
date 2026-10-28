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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

var registerMetricsOnce sync.Once

func ensureMetricsRegistered(t *testing.T) {
	t.Helper()
	registerMetricsOnce.Do(func() {
		require.NoError(t, registerPrometheusMetrics(context.Background()))
	})
}

// newTestService returns a service on 12-second slots; tests set the delays they need.
func newTestService(t *testing.T) *Service {
	t.Helper()
	ensureMetricsRegistered(t)
	s, err := newStaticDelayService(t, fixedSpecProvider{
		"SECONDS_PER_SLOT": 12 * time.Second,
		"SLOTS_PER_EPOCH":  uint64(32),
	})
	require.NoError(t, err)

	return s
}

// newAttesterDuty returns a duty for validator 1 at offset 0 of committee 0.
func newAttesterDuty(t *testing.T, slot phase0.Slot) *attester.Duty {
	t.Helper()
	duty, err := attester.NewDuty(context.Background(), slot, 1,
		[]phase0.ValidatorIndex{1}, []phase0.CommitteeIndex{0}, []uint64{0},
		map[phase0.CommitteeIndex]uint64{0: 1},
	)
	require.NoError(t, err)

	return duty
}

// TestProposerGaugeFollowsOnlyProposalDecisions checks that attester decisions never arm the proposer, and that
// the proposer gauge always shows the last proposal decision.
func TestProposerGaugeFollowsOnlyProposalDecisions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestService(t)
		s.proposerDelay = time.Second
		s.attestationPoolProvider = &sequenceAttestationPool{responses: [][]*spec.VersionedAttestation{
			{},
			recoveredAttestation(),
		}}
		headers := &headerSequenceProvider{outcomes: []headerOutcome{
			{response: &api.Response[*apiv1.BeaconBlockHeader]{Data: &apiv1.BeaconBlockHeader{}}},
			{err: &api.Error{StatusCode: 404}},
		}}
		s.beaconBlockHeadersProvider = headers
		monitorActive("proposer", false)

		require.True(t, s.ShouldAttest(context.Background(), newAttesterDuty(t, 1)))
		require.Zero(t, activeGauge(t, "proposer"))

		require.False(t, s.ShouldPropose(context.Background(), beaconblockproposer.NewDuty(1, 1)))
		require.Equal(t, 1, headers.calls)
		require.Zero(t, activeGauge(t, "proposer"))

		require.True(t, s.ShouldPropose(context.Background(), beaconblockproposer.NewDuty(2, 1)))
		require.Equal(t, float64(1), activeGauge(t, "proposer"))

		require.False(t, s.ShouldAttest(context.Background(), newAttesterDuty(t, 3)))
		require.Equal(t, float64(1), activeGauge(t, "proposer"))
	})
}

func activeGauge(t *testing.T, operation string) float64 {
	t.Helper()
	value, found := metricValue(t, "vouch_multiinstance_active", map[string]string{"operation": operation})
	require.True(t, found, "active gauge not found")

	return value
}

// metricValue returns the gauge or counter value of the series with exactly these labels, and whether it exists.
func metricValue(t *testing.T, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			series := map[string]string{}
			for _, label := range metric.Label {
				series[label.GetName()] = label.GetValue()
			}
			if maps.Equal(series, labels) {
				return metric.GetGauge().GetValue() + metric.GetCounter().GetValue(), true
			}
		}
	}

	return 0, false
}

// TestChecksTotalSeriesExistFromRegistration checks that every operation and result series is exported before its first
// count, so an increase() alert sees the first increment.
func TestChecksTotalSeriesExistFromRegistration(t *testing.T) {
	ensureMetricsRegistered(t)
	for _, operation := range []string{"attester", "proposer"} {
		for _, result := range []string{"active", "inactive", "unknown"} {
			_, found := metricValue(t, "vouch_multiinstance_checks_total", map[string]string{"operation": operation, "result": result})
			require.True(t, found, operation+"/"+result)
		}
	}
}

// TestChecksTotalCountsStartupStateOnce checks that New counts each operation's starting state once.
func TestChecksTotalCountsStartupStateOnce(t *testing.T) {
	ensureMetricsRegistered(t)
	attesterInactive := checksTotal(t, "attester", "inactive")
	proposerActive := checksTotal(t, "proposer", "active")

	// The test service starts with a 1s attester delay and no proposer delay.
	newTestService(t)
	require.Equal(t, attesterInactive+1, checksTotal(t, "attester", "inactive"))
	require.Equal(t, proposerActive+1, checksTotal(t, "proposer", "active"))
}

// TestAttesterNeverCountsUnknown checks that a failed pool read keeps the attester's fail-open behaviour and counts.
func TestAttesterNeverCountsUnknown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestService(t)
		s.attestationPoolProvider = &failingAttestationPool{}
		unknown := checksTotal(t, "attester", "unknown")
		inactive := checksTotal(t, "attester", "inactive")
		active := checksTotal(t, "attester", "active")

		require.True(t, s.ShouldAttest(context.Background(), newAttesterDuty(t, 1)))
		require.Equal(t, unknown, checksTotal(t, "attester", "unknown"))
		require.Equal(t, inactive, checksTotal(t, "attester", "inactive"))
		require.Equal(t, active+1, checksTotal(t, "attester", "active"))
	})
}

type failingAttestationPool struct{}

func (*failingAttestationPool) AttestationPool(context.Context, *api.AttestationPoolOpts) (*api.Response[[]*spec.VersionedAttestation], error) {
	return nil, errors.New("no responses received")
}

// TestDutyFailuresLeaveMetricsUnchanged checks that a failed duty neither moves the gauge, which holds the last
// decision, nor counts as a decision.
func TestDutyFailuresLeaveMetricsUnchanged(t *testing.T) {
	s := newTestService(t)
	s.attesterDelay = 0
	duty := newAttesterDuty(t, 1)
	proposerDuty := beaconblockproposer.NewDuty(1, 1)
	require.True(t, s.ShouldAttest(context.Background(), duty))
	require.True(t, s.ShouldPropose(context.Background(), proposerDuty))
	before := map[string]float64{}
	for _, operation := range []string{"attester", "proposer"} {
		for _, result := range []string{"active", "inactive", "unknown"} {
			before[operation+"/"+result] = checksTotal(t, operation, result)
		}
	}

	s.OnAttestationFailure(context.Background(), duty)
	s.OnProposalFailure(context.Background(), proposerDuty)
	require.Equal(t, float64(1), activeGauge(t, "attester"))
	require.Equal(t, float64(1), activeGauge(t, "proposer"))
	for series, count := range before {
		operation, result, _ := strings.Cut(series, "/")
		require.Equal(t, count, checksTotal(t, operation, result), series)
	}
}

func TestActiveAttesterRechecksPoolAfterPrimaryRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestService(t)
		monitorActive("attester", true)
		s.attestationPoolProvider = &sequenceAttestationPool{responses: [][]*spec.VersionedAttestation{
			recoveredAttestation(),
		}}
		duty := newAttesterDuty(t, 0)

		require.False(t, s.ShouldAttest(context.Background(), duty))
		require.Zero(t, activeGauge(t, "attester"))
	})
}

func TestAttesterActivationDoesNotBypassHealthyProposer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestService(t)
		s.proposerDelay = time.Second
		s.beaconBlockHeadersProvider = &headerSequenceProvider{outcomes: []headerOutcome{
			{response: &api.Response[*apiv1.BeaconBlockHeader]{Data: &apiv1.BeaconBlockHeader{}}},
		}}
		duty := newAttesterDuty(t, 1)

		require.True(t, s.ShouldAttest(context.Background(), duty))
		require.False(t, s.ShouldPropose(context.Background(), beaconblockproposer.NewDuty(1, 1)))
		require.Zero(t, activeGauge(t, "proposer"))
	})
}

func TestProposerTakesOverThenRelinquishesAfterPrimaryRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestService(t)
		s.proposerDelay = time.Second
		monitorActive("proposer", false)
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
	s := newTestService(t)
	provider := &headerSequenceProvider{outcomes: []headerOutcome{{err: errors.New("unexpected header lookup")}}}
	s.beaconBlockHeadersProvider = provider

	require.True(t, s.ShouldPropose(context.Background(), beaconblockproposer.NewDuty(1, 1)))
	require.Zero(t, provider.calls)
}

func TestPrimaryAttesterDoesNotWaitForPool(t *testing.T) {
	s := newTestService(t)
	s.attesterDelay = 0
	provider := &countingAttestationPool{}
	s.attestationPoolProvider = provider
	duty := newAttesterDuty(t, 1)

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

type headerSequenceProvider struct {
	outcomes []headerOutcome
	calls    int
}

type headerOutcome struct {
	response *api.Response[*apiv1.BeaconBlockHeader]
	err      error
}

func (p *headerSequenceProvider) BeaconBlockHeader(context.Context, *api.BeaconBlockHeaderOpts) (*api.Response[*apiv1.BeaconBlockHeader], error) {
	outcome := p.outcomes[p.calls]
	p.calls++

	return outcome.response, outcome.err
}

func TestProposerActivatesOnlyOnDefinitiveHeaderAbsence(t *testing.T) {
	found := &api.Response[*apiv1.BeaconBlockHeader]{Data: &apiv1.BeaconBlockHeader{}}
	tests := []struct {
		name    string
		outcome headerOutcome
		// result is the checks_total result the decision must count, once.
		result string
	}{
		{name: "BlockFound", outcome: headerOutcome{response: found}, result: "inactive"},
		{name: "NotFound", outcome: headerOutcome{err: &api.Error{StatusCode: 404}}, result: "active"},
		{name: "WrappedNotFound", outcome: headerOutcome{err: errors.Join(errors.New("no reachable beacon node has the beacon block header"), &api.Error{StatusCode: 404})}, result: "active"},
		{name: "ProviderFailure", outcome: headerOutcome{err: errors.New("unexpected provider failure")}, result: "unknown"},
		{name: "ServerError", outcome: headerOutcome{err: &api.Error{StatusCode: 503}}, result: "unknown"},
		{name: "Timeout", outcome: headerOutcome{err: context.DeadlineExceeded}, result: "unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newTestService(t)
				s.proposerDelay = time.Second
				monitorActive("proposer", true)
				s.beaconBlockHeadersProvider = &headerSequenceProvider{outcomes: []headerOutcome{test.outcome}}
				before := map[string]float64{}
				for _, result := range []string{"active", "inactive", "unknown"} {
					before[result] = checksTotal(t, "proposer", result)
				}

				require.Equal(t, test.result == "active", s.ShouldPropose(context.Background(), beaconblockproposer.NewDuty(1, 1)))
				if test.result == "active" {
					require.Equal(t, float64(1), activeGauge(t, "proposer"))
				} else {
					require.Zero(t, activeGauge(t, "proposer"))
				}
				for result, count := range before {
					want := count
					if result == test.result {
						want++
					}
					require.Equal(t, want, checksTotal(t, "proposer", result), result)
				}
			})
		})
	}
}

// TestProposerTakeoverLogsDecidingError checks that a takeover proposal is logged at info with the lookup error, so an
// operator can see which beacon nodes reported no block.
func TestProposerTakeoverLogsDecidingError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestService(t)
		var logged bytes.Buffer
		s.log = zerolog.New(&logged).Level(zerolog.InfoLevel)
		s.proposerDelay = time.Second
		s.beaconBlockHeadersProvider = &headerSequenceProvider{outcomes: []headerOutcome{{
			err: errors.Join(errors.New("no reachable beacon node has the beacon block header: missing"), &api.Error{StatusCode: 404}),
		}}}

		require.True(t, s.ShouldPropose(context.Background(), beaconblockproposer.NewDuty(1, 1)))
		var entry map[string]any
		require.NoError(t, json.Unmarshal(logged.Bytes(), &entry), logged.String())
		require.Equal(t, "info", entry["level"])
		require.Equal(t, "Beacon block header not found; activating proposer", entry["message"])
		require.Contains(t, entry["error"], "header: missing")
	})
}

// checksTotal returns vouch_multiinstance_checks_total for the operation and result, or 0 before the first count.
func checksTotal(t *testing.T, operation string, result string) float64 {
	t.Helper()
	value, _ := metricValue(t, "vouch_multiinstance_checks_total", map[string]string{"operation": operation, "result": result})

	return value
}

func TestAttesterReevaluatesAfterSuccessfulTakeover(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestService(t)
		s.attestationPoolProvider = &sequenceAttestationPool{responses: [][]*spec.VersionedAttestation{
			{},
			recoveredAttestation(),
		}}
		firstDuty := newAttesterDuty(t, 0)
		secondDuty := newAttesterDuty(t, 1)

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
