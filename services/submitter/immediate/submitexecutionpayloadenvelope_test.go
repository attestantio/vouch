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

package immediate_test

import (
	"context"
	"testing"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/submitter/immediate"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestSubmitExecutionPayloadEnvelope(t *testing.T) {
	ctx := context.Background()
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	previousTracerProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(tracerProvider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previousTracerProvider)
		require.NoError(t, tracerProvider.Shutdown(ctx))
	})
	capture := &capturingExecutionPayloadEnvelopeSubmitter{}
	service, err := immediate.New(ctx,
		immediate.WithLogLevel(zerolog.Disabled),
		immediate.WithProposalSubmitter(mock.NewProposalSubmitter()),
		immediate.WithExecutionPayloadEnvelopeSubmitter(capture),
		immediate.WithAttestationsSubmitter(mock.NewAttestationsSubmitter()),
		immediate.WithBeaconCommitteeSubscriptionsSubmitter(mock.NewBeaconCommitteeSubscriptionsSubmitter()),
		immediate.WithAggregateAttestationsSubmitter(mock.NewAggregateAttestationsSubmitter()),
		immediate.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
		immediate.WithSyncCommitteeMessagesSubmitter(mock.NewSyncCommitteeMessagesSubmitter()),
		immediate.WithSyncCommitteeSubscriptionsSubmitter(mock.NewSyncCommitteeSubscriptionsSubmitter()),
		immediate.WithSyncCommitteeContributionsSubmitter(mock.NewSyncCommitteeContributionsSubmitter()),
	)
	require.NoError(t, err)

	opts := &api.SubmitExecutionPayloadEnvelopeOpts{}
	require.NoError(t, service.SubmitExecutionPayloadEnvelope(ctx, opts))
	require.Same(t, opts, capture.opts)

	var envelopeSubmissionSpan sdktrace.ReadOnlySpan
	for _, span := range spanRecorder.Ended() {
		if span.Name() == "SubmitExecutionPayloadEnvelope" {
			envelopeSubmissionSpan = span
			break
		}
	}
	require.NotNil(t, envelopeSubmissionSpan, "submission should create an execution payload envelope span")
	require.Equal(t, "attestantio.vouch.services.submitter.immediate", envelopeSubmissionSpan.InstrumentationScope().Name)
	require.Equal(t, envelopeSubmissionSpan.SpanContext(), trace.SpanFromContext(capture.ctx).SpanContext())
}

type capturingExecutionPayloadEnvelopeSubmitter struct {
	ctx  context.Context
	opts *api.SubmitExecutionPayloadEnvelopeOpts
}

func (s *capturingExecutionPayloadEnvelopeSubmitter) SubmitExecutionPayloadEnvelope(ctx context.Context, opts *api.SubmitExecutionPayloadEnvelopeOpts) error {
	s.ctx = ctx
	s.opts = opts
	return nil
}

var _ eth2client.ExecutionPayloadEnvelopeSubmitter = (*capturingExecutionPayloadEnvelopeSubmitter)(nil)
