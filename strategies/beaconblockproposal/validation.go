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

// Package beaconblockproposal provides validation shared by proposal selection and publication.
package beaconblockproposal

import (
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/pkg/errors"
)

// ValidateEPBSProposal confirms that an ePBS proposal is usable.
func ValidateEPBSProposal(proposal *api.VersionedEPBSProposal, includePayload *bool) error {
	if proposal == nil {
		return errors.New("beacon node returned no ePBS proposal")
	}
	if includePayload != nil && *includePayload && !proposal.ExecutionPayloadIncluded {
		return errors.New("ePBS proposal excludes requested execution payload")
	}
	if proposal.Version != spec.DataVersionGloas {
		return nil
	}

	block := proposal.Gloas
	if proposal.ExecutionPayloadIncluded {
		if proposal.GloasContents == nil {
			return errors.New("ePBS proposal has no execution payload bid")
		}
		block = proposal.GloasContents.Block
	}
	if block == nil || block.Body == nil || block.Body.SignedExecutionPayloadBid == nil || block.Body.SignedExecutionPayloadBid.Message == nil {
		return errors.New("ePBS proposal has no execution payload bid")
	}
	if block.Body.SignedExecutionPayloadBid.Message.FeeRecipient.IsZero() {
		return errors.New("beacon block obtained with 0 fee recipient")
	}

	return nil
}
