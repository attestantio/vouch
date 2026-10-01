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
	"errors"
	"testing"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	mocketh2client "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/payloadattester"
	"github.com/attestantio/vouch/services/payloadattester/standard"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/attestantio/vouch/testutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestAttestFetchesSignsAndSubmitsVersionedMessages(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	data := &gloas.PayloadAttestationData{
		BeaconBlockRoot: phase0.Root{0x01},
		Slot:            12,
		PayloadPresent:  true,
	}
	client.PayloadAttestationDataFunc = func(_ context.Context, opts *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
		require.Equal(t, phase0.Slot(12), opts.Slot)
		return &api.Response[*spec.VersionedPayloadAttestationData]{Data: &spec.VersionedPayloadAttestationData{
			Version: spec.DataVersionGloas,
			Gloas:   data,
		}}, nil
	}

	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1, 2}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	signer := &recordingSigner{}
	submitter := &recordingSubmitter{}
	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.TraceLevel),
		standard.WithMonitor(prometheusMonitor{}),
		standard.WithPayloadAttestationDataProvider(client),
		standard.WithPayloadAttestationDataSigner(signer),
		standard.WithPayloadAttestationMessagesSubmitter(submitter),
	)
	require.NoError(t, err)

	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 1})
	duty.AddDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 2})
	duty.SetAccount(1, accounts[1])
	duty.SetAccount(2, accounts[2])

	messages, err := service.Attest(ctx, duty, true)
	require.NoError(t, err)
	require.Len(t, messages, 2)
	require.Len(t, signer.accounts, 2)
	require.Same(t, data, signer.data)
	require.Len(t, submitter.messages, 2)
	require.Equal(t, spec.DataVersionGloas, submitter.messages[0].Version)
	require.Equal(t, phase0.ValidatorIndex(1), submitter.messages[0].Gloas.ValidatorIndex)
	require.Equal(t, phase0.ValidatorIndex(2), submitter.messages[1].Gloas.ValidatorIndex)

	require.Equal(t, map[string]float64{"produced": 2, "signed": 2, "submitted": 2}, payloadAttestationEventCounts(t))
	require.True(t, capture.HasLog(map[string]any{"message": "Produced payload attestation data", "slot": uint64(12)}))
	require.True(t, capture.HasLog(map[string]any{"message": "Signed payload attestation messages", "slot": uint64(12), "count": 2}))
	require.True(t, capture.HasLog(map[string]any{"message": "Submitted payload attestation messages", "slot": uint64(12), "count": 2}))
}

func TestAttestRetriesUnavailablePayloadAttestationData(t *testing.T) {
	ctx := context.Background()
	client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	calls := 0
	client.PayloadAttestationDataFunc = func(_ context.Context, _ *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
		calls++
		if calls == 1 {
			return nil, eth2client.ErrNoPayloadAttestationData
		}
		return &api.Response[*spec.VersionedPayloadAttestationData]{Data: &spec.VersionedPayloadAttestationData{
			Version: spec.DataVersionGloas,
			Gloas:   &gloas.PayloadAttestationData{Slot: 12},
		}}, nil
	}
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(prometheusMonitor{}),
		standard.WithPayloadAttestationDataProvider(client),
		standard.WithPayloadAttestationDataSigner(&recordingSigner{}),
		standard.WithPayloadAttestationMessagesSubmitter(&recordingSubmitter{}),
	)
	require.NoError(t, err)
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 1})
	duty.SetAccount(1, accounts[1])

	_, err = service.Attest(ctx, duty, true)

	require.NoError(t, err)
	require.Equal(t, 2, calls)
}

func TestAttestStopsRetryingUnavailablePayloadAttestationData(t *testing.T) {
	tests := []struct {
		name     string
		cancel   bool
		minCalls int
		maxCalls int
	}{
		{
			name:     "RetryWindowElapsed",
			minCalls: 2,
			maxCalls: 11,
		},
		{
			name:     "ContextDone",
			cancel:   true,
			minCalls: 1,
			maxCalls: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := mocketh2client.New(context.Background())
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			client.PayloadAttestationDataFunc = func(context.Context, *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
				calls++
				if test.cancel {
					cancel()
				}
				return nil, eth2client.ErrNoPayloadAttestationData
			}
			accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
			require.NoError(t, err)
			signer := &recordingSigner{}
			service, err := standard.New(ctx,
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMonitor{}),
				standard.WithPayloadAttestationDataProvider(client),
				standard.WithPayloadAttestationDataSigner(signer),
				standard.WithPayloadAttestationMessagesSubmitter(&recordingSubmitter{}),
			)
			require.NoError(t, err)
			duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 1})
			duty.SetAccount(1, accounts[1])

			_, err = service.Attest(ctx, duty, true)

			require.ErrorIs(t, err, eth2client.ErrNoPayloadAttestationData)
			require.GreaterOrEqual(t, calls, test.minCalls)
			require.LessOrEqual(t, calls, test.maxCalls)
			require.Empty(t, signer.accounts)
		})
	}
}

func TestAttestReportsDataFailuresAsUnavailable(t *testing.T) {
	tests := []struct {
		name     string
		response *api.Response[*spec.VersionedPayloadAttestationData]
		err      error
	}{
		{
			name: "ProviderError",
			err:  errors.New("split-response payload attestation data responses"),
		},
		{
			name: "StillUnavailableAfterRetries",
			err:  eth2client.ErrNoPayloadAttestationData,
		},
		{
			name: "NoData",
		},
		{
			name: "NotGloas",
			response: &api.Response[*spec.VersionedPayloadAttestationData]{Data: &spec.VersionedPayloadAttestationData{
				Version: spec.DataVersionFulu,
			}},
		},
		{
			name: "WrongSlot",
			response: &api.Response[*spec.VersionedPayloadAttestationData]{Data: &spec.VersionedPayloadAttestationData{
				Version: spec.DataVersionGloas,
				Gloas:   &gloas.PayloadAttestationData{Slot: 13},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			client, err := mocketh2client.New(ctx)
			require.NoError(t, err)
			client.PayloadAttestationDataFunc = func(context.Context, *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
				return test.response, test.err
			}
			accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
			require.NoError(t, err)
			signer := &recordingSigner{}
			service, err := standard.New(ctx,
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(prometheusMonitor{}),
				standard.WithPayloadAttestationDataProvider(client),
				standard.WithPayloadAttestationDataSigner(signer),
				standard.WithPayloadAttestationMessagesSubmitter(&recordingSubmitter{}),
			)
			require.NoError(t, err)
			duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 1})
			duty.SetAccount(1, accounts[1])

			_, err = service.Attest(ctx, duty, true)

			require.ErrorIs(t, err, payloadattester.ErrPayloadAttestationDataUnavailable)
			require.Empty(t, signer.accounts)
		})
	}
}

func TestAttestReportsUnavailableDataOnlyOnLastAttempt(t *testing.T) {
	tests := []struct {
		name            string
		lastAttempt     bool
		failed          float64
		warnOrErrorLogs int
	}{
		{
			name: "EarlyAttempt",
		},
		{
			name:            "LastAttempt",
			lastAttempt:     true,
			failed:          1,
			warnOrErrorLogs: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			capture := logger.NewLogCapture()
			client, err := mocketh2client.New(ctx)
			require.NoError(t, err)
			client.PayloadAttestationDataFunc = func(context.Context, *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
				return nil, errors.New("split-response payload attestation data responses")
			}
			accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
			require.NoError(t, err)
			service, err := standard.New(ctx,
				standard.WithLogLevel(zerolog.TraceLevel),
				standard.WithMonitor(prometheusMonitor{}),
				standard.WithPayloadAttestationDataProvider(client),
				standard.WithPayloadAttestationDataSigner(&recordingSigner{}),
				standard.WithPayloadAttestationMessagesSubmitter(&recordingSubmitter{}),
			)
			require.NoError(t, err)
			duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 1})
			duty.SetAccount(1, accounts[1])
			failedBefore := payloadAttestationEventCounts(t)["failed"]

			_, err = service.Attest(ctx, duty, test.lastAttempt)

			require.ErrorIs(t, err, payloadattester.ErrPayloadAttestationDataUnavailable)
			require.Equal(t, failedBefore+test.failed, payloadAttestationEventCounts(t)["failed"])
			warnOrErrorLogs := 0
			for _, entry := range capture.Entries() {
				if entry["level"] == "warn" || entry["level"] == "error" {
					warnOrErrorLogs++
				}
			}
			require.Equal(t, test.warnOrErrorLogs, warnOrErrorLogs)
		})
	}
}

func TestAttestTracesEveryFailedRequest(t *testing.T) {
	ctx := context.Background()
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	previousTracerProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(tracerProvider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previousTracerProvider)
		require.NoError(t, tracerProvider.Shutdown(ctx))
	})
	client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	calls := 0
	client.PayloadAttestationDataFunc = func(context.Context, *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
		calls++
		if calls == 1 {
			return nil, eth2client.ErrNoPayloadAttestationData
		}
		return nil, errors.New("split-response payload attestation data responses")
	}
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(prometheusMonitor{}),
		standard.WithPayloadAttestationDataProvider(client),
		standard.WithPayloadAttestationDataSigner(&recordingSigner{}),
		standard.WithPayloadAttestationMessagesSubmitter(&recordingSubmitter{}),
	)
	require.NoError(t, err)
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 1})
	duty.SetAccount(1, accounts[1])

	_, err = service.Attest(ctx, duty, false)
	require.Error(t, err)

	failed := make(map[string]int)
	for _, span := range spanRecorder.Ended() {
		if span.Status().Code == codes.Error && len(span.Events()) > 0 {
			failed[span.Name()]++
		}
	}
	require.Equal(t, map[string]int{"PayloadAttestationData": 2, "Attest": 1}, failed)
}

func TestAttestDoesNotReportSigningOrSubmissionFailuresAsUnavailable(t *testing.T) {
	tests := []struct {
		name        string
		signer      signer.PayloadAttestationDataSigner
		submitter   submitter.PayloadAttestationMessagesSubmitter
		lastAttempt bool
	}{
		{
			name:      "EarlySigningFailure",
			signer:    failingSigner{},
			submitter: &recordingSubmitter{},
		},
		{
			name:        "LastSigningFailure",
			signer:      failingSigner{},
			submitter:   &recordingSubmitter{},
			lastAttempt: true,
		},
		{
			name:      "EarlySubmissionFailure",
			signer:    &recordingSigner{},
			submitter: failingSubmitter{},
		},
		{
			name:        "LastSubmissionFailure",
			signer:      &recordingSigner{},
			submitter:   failingSubmitter{},
			lastAttempt: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			capture := logger.NewLogCapture()
			client, err := mocketh2client.New(ctx)
			require.NoError(t, err)
			client.PayloadAttestationDataFunc = func(context.Context, *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
				return &api.Response[*spec.VersionedPayloadAttestationData]{Data: &spec.VersionedPayloadAttestationData{
					Version: spec.DataVersionGloas,
					Gloas:   &gloas.PayloadAttestationData{Slot: 12},
				}}, nil
			}
			accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
			require.NoError(t, err)
			service, err := standard.New(ctx,
				standard.WithLogLevel(zerolog.TraceLevel),
				standard.WithMonitor(prometheusMonitor{}),
				standard.WithPayloadAttestationDataProvider(client),
				standard.WithPayloadAttestationDataSigner(test.signer),
				standard.WithPayloadAttestationMessagesSubmitter(test.submitter),
			)
			require.NoError(t, err)
			duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 1})
			duty.SetAccount(1, accounts[1])
			failedBefore := payloadAttestationEventCounts(t)["failed"]

			_, err = service.Attest(ctx, duty, test.lastAttempt)

			require.Error(t, err)
			require.NotErrorIs(t, err, payloadattester.ErrPayloadAttestationDataUnavailable)
			// The caller does not retry after signing, so even an early attempt reports the failure.
			require.Equal(t, failedBefore+1, payloadAttestationEventCounts(t)["failed"])
			errorLogs := 0
			for _, entry := range capture.Entries() {
				if entry["level"] == "error" {
					errorLogs++
				}
			}
			require.Equal(t, 1, errorLogs)
		})
	}
}

func TestAttestRejectsDataForDifferentSlotBeforeSigningOrSubmitting(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	client.PayloadAttestationDataFunc = func(_ context.Context, _ *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
		return &api.Response[*spec.VersionedPayloadAttestationData]{Data: &spec.VersionedPayloadAttestationData{
			Version: spec.DataVersionGloas,
			Gloas: &gloas.PayloadAttestationData{
				Slot: 13,
			},
		}}, nil
	}

	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	signer := &recordingSigner{}
	submitter := &recordingSubmitter{}
	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.TraceLevel),
		standard.WithMonitor(prometheusMonitor{}),
		standard.WithPayloadAttestationDataProvider(client),
		standard.WithPayloadAttestationDataSigner(signer),
		standard.WithPayloadAttestationMessagesSubmitter(submitter),
	)
	require.NoError(t, err)

	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 1})
	duty.SetAccount(1, accounts[1])
	failedBefore := payloadAttestationEventCounts(t)["failed"]

	_, err = service.Attest(ctx, duty, true)
	require.EqualError(t, err, "failed to obtain payload attestation data: payload attestation data slot 13 does not match duty slot 12")
	require.Empty(t, signer.accounts)
	require.Empty(t, submitter.messages)

	require.Equal(t, failedBefore+1, payloadAttestationEventCounts(t)["failed"])
	require.True(t, capture.HasLog(map[string]any{"message": "Failed to produce payload attestation data", "slot": uint64(12)}))
}

func TestAttestRecordsSubmissionFailure(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	data := &gloas.PayloadAttestationData{Slot: 12}
	client.PayloadAttestationDataFunc = func(context.Context, *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
		return &api.Response[*spec.VersionedPayloadAttestationData]{Data: &spec.VersionedPayloadAttestationData{
			Version: spec.DataVersionGloas,
			Gloas:   data,
		}}, nil
	}

	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.TraceLevel),
		standard.WithMonitor(prometheusMonitor{}),
		standard.WithPayloadAttestationDataProvider(client),
		standard.WithPayloadAttestationDataSigner(&recordingSigner{}),
		standard.WithPayloadAttestationMessagesSubmitter(failingSubmitter{}),
	)
	require.NoError(t, err)
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 1})
	duty.SetAccount(1, accounts[1])
	failedBefore := payloadAttestationEventCounts(t)["failed"]

	_, err = service.Attest(ctx, duty, true)

	require.EqualError(t, err, "failed to submit payload attestation messages: submission failed")
	require.Equal(t, failedBefore+1, payloadAttestationEventCounts(t)["failed"])
	require.True(t, capture.HasLog(map[string]any{"message": "Failed to submit payload attestation messages", "slot": uint64(12)}))
}

func TestPrepareRecordsScheduledPayloadAttestation(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	service, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.TraceLevel),
		standard.WithMonitor(prometheusMonitor{}),
		standard.WithPayloadAttestationDataProvider(client),
		standard.WithPayloadAttestationDataSigner(&recordingSigner{}),
		standard.WithPayloadAttestationMessagesSubmitter(&recordingSubmitter{}),
	)
	require.NoError(t, err)
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 1})
	duty.AddDuty(&apiv1.PTCDuty{Slot: 12, ValidatorIndex: 2})
	preparedBefore := payloadAttestationEventCounts(t)["scheduled"]

	require.NoError(t, service.Prepare(ctx, duty))

	require.Equal(t, preparedBefore+2, payloadAttestationEventCounts(t)["scheduled"])
	require.True(t, capture.HasLog(map[string]any{"message": "Scheduled payload attestations", "slot": uint64(12), "count": 2}))
}

func payloadAttestationEventCounts(t *testing.T) map[string]float64 {
	t.Helper()

	eventCounts := make(map[string]float64)
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, family := range metricFamilies {
		if family.GetName() != "vouch_payloadattestation_process_events_total" {
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

type recordingSigner struct {
	accounts []e2wtypes.Account
	data     *gloas.PayloadAttestationData
}

func (s *recordingSigner) SignPayloadAttestationData(_ context.Context, accounts []e2wtypes.Account, data *gloas.PayloadAttestationData) ([]phase0.BLSSignature, error) {
	s.accounts = accounts
	s.data = data
	sigs := make([]phase0.BLSSignature, len(accounts))
	for i := range sigs {
		sigs[i][0] = byte(i + 1)
	}
	return sigs, nil
}

type failingSigner struct{}

func (failingSigner) SignPayloadAttestationData(context.Context, []e2wtypes.Account, *gloas.PayloadAttestationData) ([]phase0.BLSSignature, error) {
	return nil, errors.New("signing failed")
}

type recordingSubmitter struct {
	messages []*spec.VersionedPayloadAttestationMessage
}

type failingSubmitter struct{}

func (failingSubmitter) SubmitPayloadAttestationMessages(context.Context, *api.SubmitPayloadAttestationMessagesOpts) error {
	return errors.New("submission failed")
}

func (s *recordingSubmitter) SubmitPayloadAttestationMessages(_ context.Context, opts *api.SubmitPayloadAttestationMessagesOpts) error {
	s.messages = opts.Messages
	return nil
}
