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
)

func TestSubmitExecutionPayloadEnvelope(t *testing.T) {
	ctx := context.Background()
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
}

type capturingExecutionPayloadEnvelopeSubmitter struct {
	opts *api.SubmitExecutionPayloadEnvelopeOpts
}

func (s *capturingExecutionPayloadEnvelopeSubmitter) SubmitExecutionPayloadEnvelope(_ context.Context, opts *api.SubmitExecutionPayloadEnvelopeOpts) error {
	s.opts = opts
	return nil
}

var _ eth2client.ExecutionPayloadEnvelopeSubmitter = (*capturingExecutionPayloadEnvelopeSubmitter)(nil)
