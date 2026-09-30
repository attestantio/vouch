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

package beaconblockproposal

import (
	"time"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/rs/zerolog"
)

// ProviderOutcome is one provider's answer to an ePBS proposal request.
type ProviderOutcome struct {
	Provider  string
	Slot      phase0.Slot
	RequestID string
	// Proposal is nil if the provider returned none.
	Proposal        *api.VersionedEPBSProposal
	Metadata        map[string]any
	Elapsed         time.Duration
	Outcome         string
	RejectionReason string
	Err             error
}

// LogProviderOutcome logs a provider's outcome.  Proposal details are logged only when the
// proposal is well formed, and builder_index only when it carries a bid, so a missing value is
// never reported as zero.
func LogProviderOutcome(log zerolog.Logger, outcome *ProviderOutcome) {
	event := log.Info().
		Uint64("slot", uint64(outcome.Slot)).
		Str("request_id", outcome.RequestID).
		Str("provider", beaconblockproposer.StableProviderName(outcome.Provider)).
		Dur("latency", outcome.Elapsed).
		Str("outcome", outcome.Outcome).
		Str("rejection_reason", outcome.RejectionReason)
	if outcome.Err != nil {
		event = event.Str("error", beaconblockproposer.SafeError(outcome.Err, outcome.Provider))
	}
	beaconblockproposer.WithClientDetails(event, outcome.Provider)

	proposal := outcome.Proposal
	if proposal == nil {
		logUnknownProposal(event)

		return
	}
	signedBid, bidErr := EPBSProposalBid(proposal)
	if bidErr != nil && proposal.Version == spec.DataVersionGloas {
		logUnknownProposal(event)

		return
	}

	if bidErr == nil {
		event = event.Uint64("builder_index", uint64(signedBid.Message.BuilderIndex))
	}
	proposalRoot := "unknown"
	if root, err := proposal.Root(); err == nil {
		proposalRoot = root.String()
	}
	executionValue := "unknown"
	if proposal.ExecutionValue != nil {
		executionValue = proposal.ExecutionValue.String()
	}
	event.Str("proposal_root", proposalRoot).
		Str("source", EPBSProposalSource(proposal, outcome.Metadata)).
		Bool("value_known", proposal.ExecutionValue != nil).
		Str("execution_value", executionValue).
		Bool("payload_included", proposal.ExecutionPayloadIncluded).
		Bool("builder_url_present", beaconblockproposer.BuilderURLPresent(outcome.Metadata)).
		Msg("ePBS proposal provider completed")
}

func logUnknownProposal(event *zerolog.Event) {
	event.Str("proposal_root", "unknown").
		Str("source", "unknown").
		Bool("value_known", false).
		Str("execution_value", "unknown").
		Bool("payload_included", false).
		Bool("builder_url_present", false).
		Msg("ePBS proposal provider completed")
}
