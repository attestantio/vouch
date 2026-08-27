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

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	mocketh2client "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/payloadattester"
	"github.com/attestantio/vouch/services/payloadattester/standard"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/attestantio/vouch/testutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
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

	messages, err := service.Attest(ctx, duty)
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

	_, err = service.Attest(ctx, duty)
	require.EqualError(t, err, "payload attestation data slot 13 does not match duty slot 12")
	require.Empty(t, signer.accounts)
	require.Empty(t, submitter.messages)

	require.Equal(t, float64(1), payloadAttestationEventCounts(t)["failed"])
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

	_, err = service.Attest(ctx, duty)

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
