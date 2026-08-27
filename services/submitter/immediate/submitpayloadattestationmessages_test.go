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

	"github.com/attestantio/go-eth2-client/api"
	mocketh2client "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/vouch/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/submitter/immediate"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSubmitPayloadAttestationMessagesForwardsRequest(t *testing.T) {
	ctx := context.Background()
	client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	proposalSubmitter := mock.NewProposalSubmitter()
	recorder := &recordingPayloadAttestationSubmitter{}

	service, err := immediate.New(ctx,
		immediate.WithLogLevel(zerolog.Disabled),
		immediate.WithClientMonitor(nullmetrics.New()),
		immediate.WithProposalSubmitter(proposalSubmitter),
		immediate.WithExecutionPayloadEnvelopeSubmitter(client),
		immediate.WithAttestationsSubmitter(client),
		immediate.WithBeaconCommitteeSubscriptionsSubmitter(client),
		immediate.WithAggregateAttestationsSubmitter(client),
		immediate.WithProposalPreparationsSubmitter(client),
		immediate.WithSyncCommitteeMessagesSubmitter(client),
		immediate.WithSyncCommitteeSubscriptionsSubmitter(client),
		immediate.WithSyncCommitteeContributionsSubmitter(client),
		immediate.WithPayloadAttestationMessagesSubmitter(recorder),
	)
	require.NoError(t, err)

	message := &spec.VersionedPayloadAttestationMessage{
		Version: spec.DataVersionGloas,
		Gloas: &gloas.PayloadAttestationMessage{
			ValidatorIndex: 7,
			Data:           &gloas.PayloadAttestationData{Slot: 9},
		},
	}
	opts := &api.SubmitPayloadAttestationMessagesOpts{Messages: []*spec.VersionedPayloadAttestationMessage{message}}
	require.NoError(t, service.SubmitPayloadAttestationMessages(ctx, opts))
	require.Same(t, opts, recorder.opts)
}

type recordingPayloadAttestationSubmitter struct {
	opts *api.SubmitPayloadAttestationMessagesOpts
}

func (s *recordingPayloadAttestationSubmitter) SubmitPayloadAttestationMessages(_ context.Context, opts *api.SubmitPayloadAttestationMessagesOpts) error {
	s.opts = opts
	return nil
}
