// Copyright © 2020 - 2024 Attestant Limited.
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

package null

import (
	"context"
	"encoding/json"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the submitter for signed items.
type Service struct {
	log zerolog.Logger
}

// New creates a new submitter.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters := parseAndCheckParameters(params...)

	// Set logging.
	log := zerologger.With().Str("service", "submitter").Str("impl", "null").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		log: log,
	}

	return s, nil
}

// SubmitProposal submits a proposal.
func (s *Service) SubmitProposal(_ context.Context, proposal *api.VersionedSignedProposal) error {
	if proposal == nil {
		return errors.New("no proposal supplied")
	}

	if e := s.log.Trace(); e.Enabled() {
		data, err := json.Marshal(proposal)
		if err == nil {
			e.Str("block", string(data)).Msg("Not submitting proposal")
		}
	}

	return nil
}

// SubmitAttestations submits multiple attestations.
func (s *Service) SubmitAttestations(_ context.Context, attestations []*phase0.Attestation) error {
	if len(attestations) == 0 {
		return errors.New("no attestations supplied")
	}

	if e := s.log.Trace(); e.Enabled() {
		data, err := json.Marshal(attestations)
		if err == nil {
			e.Str("attestations", string(data)).Msg("Not submitting attestations")
		}
	}

	return nil
}

// SubmitBeaconCommitteeSubscriptions submits a batch of beacon committee subscriptions.
func (s *Service) SubmitBeaconCommitteeSubscriptions(_ context.Context, subscriptions []*apiv1.BeaconCommitteeSubscription) error {
	if subscriptions == nil {
		return errors.New("no subscriptions supplied")
	}

	if e := s.log.Trace(); e.Enabled() {
		// Summary counts.
		aggregating := 0
		for i := range subscriptions {
			if subscriptions[i].IsAggregator {
				aggregating++
			}
		}

		data, err := json.Marshal(subscriptions)
		if err == nil {
			e.Str("subscriptions", string(data)).Int("subscribing", len(subscriptions)).Int("aggregating", aggregating).Msg("Not submitting subscriptions")
		}
	}

	return nil
}

// SubmitAggregateAttestations submits aggregate attestations.
func (s *Service) SubmitAggregateAttestations(_ context.Context, aggregates []*phase0.SignedAggregateAndProof) error {
	if len(aggregates) == 0 {
		return errors.New("no aggregate attestations supplied")
	}

	if e := s.log.Trace(); e.Enabled() {
		data, err := json.Marshal(aggregates)
		if err == nil {
			e.Str("attestation", string(data)).Msg("Not submitting aggregate attestations")
		}
	}

	return nil
}

// SubmitProposalPreparations submits proposal preparations.
func (s *Service) SubmitProposalPreparations(_ context.Context, preparations []*apiv1.ProposalPreparation) error {
	if len(preparations) == 0 {
		return errors.New("no preparations supplied")
	}

	if e := s.log.Trace(); e.Enabled() {
		data, err := json.Marshal(preparations)
		if err == nil {
			e.Str("preparations", string(data)).Msg("Not submitting proposal preparations")
		}
	}

	return nil
}

// SubmitSyncCommitteeMessages submits sync committee messages.
func (s *Service) SubmitSyncCommitteeMessages(_ context.Context, messages []*altair.SyncCommitteeMessage) error {
	if len(messages) == 0 {
		return errors.New("no sync committee messages supplied")
	}

	if e := s.log.Trace(); e.Enabled() {
		data, err := json.Marshal(messages)
		if err == nil {
			e.Str("messages", string(data)).Msg("Not submitting sync committee messages")
		}
	}

	return nil
}

// SubmitSyncCommitteeSubscriptions submits a batch of sync committee subscriptions.
func (s *Service) SubmitSyncCommitteeSubscriptions(_ context.Context, subscriptions []*apiv1.SyncCommitteeSubscription) error {
	if len(subscriptions) == 0 {
		return errors.New("no sync committee subscriptions supplied")
	}

	if e := s.log.Trace(); e.Enabled() {
		data, err := json.Marshal(subscriptions)
		if err == nil {
			e.Str("subscriptions", string(data)).Msg("Not submitting sync committee subscriptions")
		}
	}

	return nil
}

// SubmitSyncCommitteeContributions submits sync committee contributions.
func (s *Service) SubmitSyncCommitteeContributions(_ context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error {
	if len(contributionAndProofs) == 0 {
		return errors.New("no sync committee contribution and proofs supplied")
	}

	if e := s.log.Trace(); e.Enabled() {
		data, err := json.Marshal(contributionAndProofs)
		if err == nil {
			e.Str("contribution_and_proofs", string(data)).Msg("Not submitting sync committee contribution and proofs")
		}
	}

	return nil
}
