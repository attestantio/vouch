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
	"sync/atomic"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/proposerpreferences"
	"github.com/attestantio/vouch/services/proposerpreferences/standard"
	"github.com/attestantio/vouch/testutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestPublishSignsAndSubmitsEachDistinctPreferenceOnce(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	signer := &recordingSigner{signature: phase0.BLSSignature{0x01}}
	submitter := &recordingSubmitter{outcomes: map[string]error{"one": nil, "two": nil}}
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(signer),
		standard.WithSubmitter(submitter),
	)
	require.NoError(t, err)

	duty := proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	)

	require.NoError(t, service.Publish(ctx, duty))
	require.NoError(t, service.Publish(ctx, duty))

	require.Len(t, signer.preferences, 1)
	require.Equal(t, &gloas.ProposerPreferences{
		DependentRoot:  phase0.Root{0x01},
		ProposalSlot:   64,
		ValidatorIndex: 3,
		FeeRecipient:   bellatrix.ExecutionAddress{0x02},
		TargetGasLimit: 30_000_000,
	}, signer.preferences[0])
	require.Len(t, submitter.preferences, 1)
	require.Equal(t, signer.signature, submitter.preferences[0][0].Signature)
	require.Same(t, signer.preferences[0], submitter.preferences[0][0].Message)
}

func TestProviderReadyDoesNotWaitForPreferenceSubmission(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	submitter := &blockingSubmitter{started: make(chan struct{}), release: make(chan struct{})}
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(&recordingSigner{signature: phase0.BLSSignature{0x01}}),
		standard.WithSubmitter(submitter),
	)
	require.NoError(t, err)
	errCh := make(chan error, 1)
	go func() {
		errCh <- service.Publish(ctx, proposerpreferences.NewDuty(
			phase0.Root{0x01},
			64,
			3,
			accounts[3],
			bellatrix.ExecutionAddress{0x02},
			30_000_000,
		))
	}()
	<-submitter.started

	readyCh := make(chan bool, 1)
	go func() {
		readyCh <- service.ProviderReady("accepted", 64, 3)
	}()
	select {
	case ready := <-readyCh:
		require.False(t, ready)
	case <-time.After(time.Second):
		t.Fatal("provider readiness waited for preference submission")
	}
	close(submitter.release)
	require.NoError(t, <-errCh)
}

func TestConcurrentPublishReusesInFlightPreference(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	signer := &recordingSigner{signature: phase0.BLSSignature{0x01}}
	submitter := &blockingSubmitter{started: make(chan struct{}), release: make(chan struct{})}
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(signer),
		standard.WithSubmitter(submitter),
	)
	require.NoError(t, err)
	duty := proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	)
	errs := make(chan error, 2)
	go func() { errs <- service.Publish(ctx, duty) }()
	<-submitter.started
	go func() { errs <- service.Publish(ctx, duty) }()

	close(submitter.release)
	require.NoError(t, <-errs)
	require.NoError(t, <-errs)

	require.Len(t, signer.preferences, 1)
	require.Equal(t, int64(1), submitter.calls.Load())
}

func TestPruneRetainsInFlightPreference(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	signer := &recordingSigner{signature: phase0.BLSSignature{0x01}}
	submitter := &blockingSubmitter{started: make(chan struct{}), release: make(chan struct{})}
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(signer),
		standard.WithSubmitter(submitter),
	)
	require.NoError(t, err)
	errCh := make(chan error, 1)
	go func() {
		errCh <- service.Publish(ctx, proposerpreferences.NewDuty(
			phase0.Root{0x01},
			64,
			3,
			accounts[3],
			bellatrix.ExecutionAddress{0x02},
			30_000_000,
		))
	}()
	<-submitter.started

	service.Prune(65)
	close(submitter.release)
	require.NoError(t, <-errCh)

	require.True(t, service.ProviderReady("accepted", 64, 3))
	require.Len(t, signer.preferences, 1)
}

func TestProviderReadyAfterAcceptedSubmission(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	submitter := &recordingSubmitter{outcomes: map[string]error{"accepted": nil, "rejected": context.DeadlineExceeded}}
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(&recordingSigner{signature: phase0.BLSSignature{0x01}}),
		standard.WithSubmitter(submitter),
	)
	require.NoError(t, err)

	err = service.Publish(ctx, proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	))
	require.NoError(t, err)
	require.True(t, service.ProviderReady("accepted", 64, 3))
	require.False(t, service.ProviderReady("rejected", 64, 3))
}

func TestDependentRootChangeRejectsStalePreferenceReplay(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(&recordingSigner{signature: phase0.BLSSignature{0x01}}),
		standard.WithSubmitter(&recordingSubmitter{outcomes: map[string]error{"accepted": nil}}),
	)
	require.NoError(t, err)
	require.NoError(t, service.Publish(ctx, proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	)))
	require.True(t, service.ProviderReady("accepted", 64, 3))

	service.UpdateDependentRoot(64, 95, phase0.Root{0x02})

	require.False(t, service.ProviderReady("accepted", 64, 3))
	require.NoError(t, service.Publish(ctx, proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	)))
	require.False(t, service.ProviderReady("accepted", 64, 3))
	require.NoError(t, service.Publish(ctx, proposerpreferences.NewDuty(
		phase0.Root{0x02},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	)))
	require.True(t, service.ProviderReady("accepted", 64, 3))
}

func TestDependentRootChangeKeepsInFlightStalePreferenceUnready(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	submitter := &blockingSubmitter{started: make(chan struct{}), release: make(chan struct{})}
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(&recordingSigner{signature: phase0.BLSSignature{0x01}}),
		standard.WithSubmitter(submitter),
	)
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() {
		errCh <- service.Publish(ctx, proposerpreferences.NewDuty(
			phase0.Root{0x01},
			64,
			3,
			accounts[3],
			bellatrix.ExecutionAddress{0x02},
			30_000_000,
		))
	}()
	<-submitter.started

	service.UpdateDependentRoot(64, 95, phase0.Root{0x02})
	close(submitter.release)
	require.NoError(t, <-errCh)

	require.False(t, service.ProviderReady("accepted", 64, 3))
}

func TestSimpleProviderReadyAfterAllPreferencesAccepted(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(&recordingSigner{signature: phase0.BLSSignature{0x01}}),
		standard.WithSubmitter(&recordingSubmitter{outcomes: map[string]error{"one": nil, "two": nil}}),
	)
	require.NoError(t, err)

	require.NoError(t, service.Publish(ctx, proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	)))

	require.True(t, service.ProviderReady("simple", 64, 3))
}

func TestPruneDropsExpiredPreferences(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(&recordingSigner{signature: phase0.BLSSignature{0x01}}),
		standard.WithSubmitter(&recordingSubmitter{outcomes: map[string]error{"accepted": nil}}),
	)
	require.NoError(t, err)
	require.NoError(t, service.Publish(ctx, proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	)))
	pruner, ok := any(service).(interface{ Prune(phase0.Slot) })
	require.True(t, ok)

	pruner.Prune(65)

	require.False(t, service.ProviderReady("accepted", 64, 3))
}

func TestPublishRetriesOnlyRejectedProvider(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	submitter := &recordingSubmitter{outcomeSets: []map[string]error{
		{"accepted": nil, "rejected": context.DeadlineExceeded},
		{"rejected": nil},
	}}
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(&recordingSigner{signature: phase0.BLSSignature{0x01}}),
		standard.WithSubmitter(submitter),
	)
	require.NoError(t, err)
	duty := proposerpreferences.NewDuty(phase0.Root{0x01}, 64, 3, accounts[3], bellatrix.ExecutionAddress{0x02}, 30_000_000)

	require.NoError(t, service.Publish(ctx, duty))
	require.NoError(t, service.Publish(ctx, duty))
	require.Equal(t, [][]string{nil, {"rejected"}}, submitter.providers)
}

func TestPublishSubmissionOutcomes(t *testing.T) {
	tests := []struct {
		name        string
		outcomeSets []map[string]error
		err         string
	}{
		{
			name:        "SomeProvidersAccept",
			outcomeSets: []map[string]error{{"accepted": nil, "rejected": context.DeadlineExceeded}},
		},
		{
			name:        "NoProviderAccepts",
			outcomeSets: []map[string]error{{"one": context.DeadlineExceeded, "two": context.DeadlineExceeded}},
			err:         "failed to submit proposer preferences: context deadline exceeded",
		},
		{
			name: "RetryFailsAfterEarlierAcceptance",
			outcomeSets: []map[string]error{
				{"accepted": nil, "rejected": context.DeadlineExceeded},
				{"rejected": context.DeadlineExceeded},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
			require.NoError(t, err)
			service, err := standard.New(ctx,
				standard.WithMonitor(nullmetrics.New()),
				standard.WithSigner(&recordingSigner{signature: phase0.BLSSignature{0x01}}),
				standard.WithSubmitter(&recordingSubmitter{outcomeSets: test.outcomeSets}),
			)
			require.NoError(t, err)
			duty := proposerpreferences.NewDuty(phase0.Root{0x01}, 64, 3, accounts[3], bellatrix.ExecutionAddress{0x02}, 30_000_000)

			for range test.outcomeSets[1:] {
				_ = service.Publish(ctx, duty)
			}
			err = service.Publish(ctx, duty)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPublishRecordsProviderOutcomes(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service, err := standard.New(ctx,
		standard.WithMonitor(prometheusMonitor{}),
		standard.WithSigner(&recordingSigner{signature: phase0.BLSSignature{0x01}}),
		standard.WithSubmitter(&recordingSubmitter{outcomes: map[string]error{"accepted": nil, "rejected": context.DeadlineExceeded}}),
	)
	require.NoError(t, err)
	before := proposerPreferencesEventCounts(t)

	err = service.Publish(ctx, proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	))

	require.NoError(t, err)
	require.Equal(t, before["signed"]+1, proposerPreferencesEventCounts(t)["signed"])
	require.Equal(t, before["accepted"]+1, proposerPreferencesEventCounts(t)["accepted"])
	require.Equal(t, before["rejected"]+1, proposerPreferencesEventCounts(t)["rejected"])
}

func TestPublishRecordsPreferenceReplay(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service, err := standard.New(ctx,
		standard.WithMonitor(prometheusMonitor{}),
		standard.WithSigner(&recordingSigner{signature: phase0.BLSSignature{0x01}}),
		standard.WithSubmitter(&recordingSubmitter{outcomes: map[string]error{"accepted": nil}}),
	)
	require.NoError(t, err)
	duty := proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	)
	replayedBefore := proposerPreferencesEventCounts(t)["replayed"]

	require.NoError(t, service.Publish(ctx, duty))
	require.NoError(t, service.Publish(ctx, duty))

	require.Equal(t, replayedBefore+1, proposerPreferencesEventCounts(t)["replayed"])
}

func TestPublishRecordsPreferenceRefresh(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service, err := standard.New(ctx,
		standard.WithMonitor(prometheusMonitor{}),
		standard.WithSigner(&recordingSigner{signature: phase0.BLSSignature{0x01}}),
		standard.WithSubmitter(&recordingSubmitter{outcomes: map[string]error{"accepted": nil}}),
	)
	require.NoError(t, err)
	refreshedBefore := proposerPreferencesEventCounts(t)["refreshed"]

	require.NoError(t, service.Publish(ctx, proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	)))
	require.NoError(t, service.Publish(ctx, proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		31_000_000,
	)))

	require.Equal(t, refreshedBefore+1, proposerPreferencesEventCounts(t)["refreshed"])
}

func TestPublishRejectsMissingProviderOutcomes(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{3}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service, err := standard.New(ctx,
		standard.WithMonitor(nullmetrics.New()),
		standard.WithSigner(&recordingSigner{}),
		standard.WithSubmitter(&recordingSubmitter{}),
	)
	require.NoError(t, err)

	err = service.Publish(ctx, proposerpreferences.NewDuty(
		phase0.Root{0x01},
		64,
		3,
		accounts[3],
		bellatrix.ExecutionAddress{0x02},
		30_000_000,
	))

	require.EqualError(t, err, "no proposer preferences submission outcomes")
}

func proposerPreferencesEventCounts(t *testing.T) map[string]float64 {
	t.Helper()

	eventCounts := make(map[string]float64)
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, family := range metricFamilies {
		if family.GetName() != "vouch_proposerpreferences_process_events_total" {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "outcome" {
					eventCounts[label.GetValue()] = metric.GetCounter().GetValue()
				}
			}
		}
	}

	return eventCounts
}

type prometheusMonitor struct{}

func (prometheusMonitor) Presenter() string {
	return "prometheus"
}

type blockingSubmitter struct {
	calls   atomic.Int64
	started chan struct{}
	release chan struct{}
}

func (s *blockingSubmitter) SubmitProposerPreferences(_ context.Context, _ []*gloas.SignedProposerPreferences, _ []string) map[string]error {
	s.calls.Add(1)
	close(s.started)
	<-s.release
	return map[string]error{"accepted": nil}
}

type recordingSigner struct {
	preferences []*gloas.ProposerPreferences
	signature   phase0.BLSSignature
}

func (s *recordingSigner) SignProposerPreferences(_ context.Context,
	_ e2wtypes.Account,
	preferences *gloas.ProposerPreferences,
) (
	phase0.BLSSignature,
	error,
) {
	s.preferences = append(s.preferences, preferences)
	return s.signature, nil
}

type recordingSubmitter struct {
	preferences [][]*gloas.SignedProposerPreferences
	providers   [][]string
	outcomes    map[string]error
	outcomeSets []map[string]error
}

func (s *recordingSubmitter) SubmitProposerPreferences(_ context.Context,
	preferences []*gloas.SignedProposerPreferences,
	providers []string,
) map[string]error {
	s.preferences = append(s.preferences, preferences)
	s.providers = append(s.providers, providers)
	if len(s.outcomeSets) > 0 {
		outcomes := s.outcomeSets[0]
		s.outcomeSets = s.outcomeSets[1:]
		return outcomes
	}
	return s.outcomes
}
