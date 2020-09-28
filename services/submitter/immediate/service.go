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

package immediate

import (
	"context"
	"encoding/json"

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the submitter for signed items.
type Service struct {
	attestationSubmitter                  eth2client.AttestationSubmitter
	beaconBlockSubmitter                  eth2client.BeaconBlockSubmitter
	beaconCommitteeSubscriptionsSubmitter eth2client.BeaconCommitteeSubscriptionsSubmitter
	aggregateAttestationsSubmitter        eth2client.AggregateAttestationsSubmitter
}

// module-wide log.
var log zerolog.Logger

// New creates a new submitter.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "submitter").Str("impl", "immediate").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		attestationSubmitter:                  parameters.attestationSubmitter,
		beaconBlockSubmitter:                  parameters.beaconBlockSubmitter,
		beaconCommitteeSubscriptionsSubmitter: parameters.beaconCommitteeSubscriptionsSubmitter,
		aggregateAttestationsSubmitter:        parameters.aggregateAttestationsSubmitter,
	}

	return s, nil
}

// SubmitBeaconBlock submits a block.
func (s *Service) SubmitBeaconBlock(ctx context.Context, block *spec.SignedBeaconBlock) error {
	if block == nil {
		return errors.New("no beacon block supplied")
	}

	if err := s.beaconBlockSubmitter.SubmitBeaconBlock(ctx, block); err != nil {
		return errors.Wrap(err, "failed to submit beacon block")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(block)
		if err == nil {
			e.Str("block", string(data)).Msg("Submitted beacon block")
		}
	}

	return nil
}

// SubmitAttestation submits an attestation.
func (s *Service) SubmitAttestation(ctx context.Context, attestation *spec.Attestation) error {
	if attestation == nil {
		return errors.New("no attestation supplied")
	}

	if err := s.attestationSubmitter.SubmitAttestation(ctx, attestation); err != nil {
		return errors.Wrap(err, "failed to submit attestation")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(attestation)
		if err == nil {
			e.Str("attestation", string(data)).Msg("Submitted attestation")
		}
	}

	return nil
}

// SubmitBeaconCommitteeSubscriptions submits a batch of beacon committee subscriptions.
func (s *Service) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*submitter.BeaconCommitteeSubscription) error {
	if subscriptions == nil {
		return errors.New("no subscriptions supplied")
	}

	subs := make([]*eth2client.BeaconCommitteeSubscription, len(subscriptions))
	for i, subscription := range subscriptions {
		subs[i] = &eth2client.BeaconCommitteeSubscription{
			Slot:                   subscription.Slot,
			CommitteeIndex:         subscription.CommitteeIndex,
			CommitteeSize:          subscription.CommitteeSize,
			ValidatorIndex:         subscription.ValidatorIndex,
			ValidatorPubKey:        subscription.ValidatorPubKey,
			Aggregate:              subscription.Aggregate,
			SlotSelectionSignature: subscription.Signature,
		}
	}
	if err := s.beaconCommitteeSubscriptionsSubmitter.SubmitBeaconCommitteeSubscriptions(ctx, subs); err != nil {
		return errors.Wrap(err, "failed to submit beacon committee subscriptions")
	}

	if e := log.Trace(); e.Enabled() {
		// Summary counts.
		aggregating := 0
		for i := range subscriptions {
			if subscriptions[i].Aggregate {
				aggregating++
			}
		}

		data, err := json.Marshal(subscriptions)
		if err == nil {
			e.Str("subscriptions", string(data)).Int("subscribing", len(subscriptions)).Int("aggregating", aggregating).Msg("Submitted subscriptions")
		}
	}

	return nil
}

// SubmitAggregateAttestation submits an aggregate attestation.
func (s *Service) SubmitAggregateAttestation(ctx context.Context, aggregate *spec.SignedAggregateAndProof) error {
	if aggregate == nil {
		return errors.New("no aggregate attestation supplied")
	}

	if err := s.aggregateAttestationsSubmitter.SubmitAggregateAttestations(ctx, []*spec.SignedAggregateAndProof{aggregate}); err != nil {
		return errors.Wrap(err, "failed to submit aggregate attestation")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(aggregate)
		if err == nil {
			e.Str("attestation", string(data)).Msg("Submitted aggregate attestation")
		}
	}

	return nil
}
