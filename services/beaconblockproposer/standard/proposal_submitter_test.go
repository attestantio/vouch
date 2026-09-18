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

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
)

type proposalSubmitter struct {
	client eth2client.ProposalSubmitter
}

func (s *proposalSubmitter) SubmitProposal(ctx context.Context, proposal *api.VersionedSignedProposal) error {
	return s.client.SubmitProposal(ctx, &api.SubmitProposalOpts{Proposal: proposal})
}
