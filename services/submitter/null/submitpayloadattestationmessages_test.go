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

package null_test

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/vouch/services/submitter/null"
	"github.com/stretchr/testify/require"
)

func TestSubmitPayloadAttestationMessagesAcceptsMessages(t *testing.T) {
	service, err := null.New(context.Background())
	require.NoError(t, err)

	err = service.SubmitPayloadAttestationMessages(context.Background(), &api.SubmitPayloadAttestationMessagesOpts{
		Messages: []*spec.VersionedPayloadAttestationMessage{{
			Version: spec.DataVersionGloas,
			Gloas: &gloas.PayloadAttestationMessage{
				Data: &gloas.PayloadAttestationData{Slot: 1},
			},
		}},
	})
	require.NoError(t, err)
}
