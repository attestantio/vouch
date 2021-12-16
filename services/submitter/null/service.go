// Copyright © 2020 Attestant Limited.
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

	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the submitter for signed items.
type Service struct{}

// module-wide log.
var log zerolog.Logger

// New creates a new submitter.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "submitter").Str("impl", "null").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{}

	return s, nil
}

// SubmitBeaconBlock submits a block.
func (*Service) SubmitBeaconBlock(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
	if block == nil {
		return errors.New("no beacon block supplied")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(block)
		if err == nil {
			e.Str("block", string(data)).Msg("Not submitting beacon block")
		}
	}

	return nil
}

// SubmitAttestations submits multiple attestations.
func (*Service) SubmitAttestations(ctx context.Context, attestations []*phase0.Attestation) error {
	if len(attestations) == 0 {
		return errors.New("no attestations supplied")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(attestations)
		if err == nil {
			e.Str("attestations", string(data)).Msg("Not submitting attestations")
		}
	}

	return nil
}

// SubmitBeaconCommitteeSubscriptions submits a batch of beacon committee subscriptions.
func (*Service) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*api.BeaconCommitteeSubscription) error {
	if subscriptions == nil {
		return errors.New("no subscriptions supplied")
	}

	if e := log.Trace(); e.Enabled() {
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
func (*Service) SubmitAggregateAttestations(ctx context.Context, aggregates []*phase0.SignedAggregateAndProof) error {
	if len(aggregates) == 0 {
		return errors.New("no aggregate attestations supplied")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(aggregates)
		if err == nil {
			e.Str("attestation", string(data)).Msg("Not submitting aggregate attestations")
		}
	}

	return nil
}

// SubmitSyncCommitteeMessages submits sync committee messages.
func (*Service) SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
	if len(messages) == 0 {
		return errors.New("no sync committee messages supplied")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(messages)
		if err == nil {
			e.Str("messages", string(data)).Msg("Not submitting sync committee messages")
		}
	}

	return nil
}

// SubmitSyncCommitteeSubscriptions submits a batch of sync committee subscriptions.
func (*Service) SubmitSyncCommitteeSubscriptions(ctx context.Context, subscriptions []*api.SyncCommitteeSubscription) error {
	if len(subscriptions) == 0 {
		return errors.New("no sync committee subscriptions supplied")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(subscriptions)
		if err == nil {
			e.Str("subscriptions", string(data)).Msg("Not submitting sync committee subscriptions")
		}
	}

	return nil
}

// SubmitSyncCommitteeContributions submits sync committee contributions.
func (*Service) SubmitSyncCommitteeContributions(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error {
	if len(contributionAndProofs) == 0 {
		return errors.New("no sync committee contribution and proofs supplied")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(contributionAndProofs)
		if err == nil {
			e.Str("contribution_and_proofs", string(data)).Msg("Not submitting sync committee contribution and proofs")
		}
	}

	return nil
}
