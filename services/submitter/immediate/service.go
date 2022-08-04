// Copyright © 2020, 2022 Attestant Limited.
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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the submitter for signed items.
type Service struct {
	clientMonitor                         metrics.ClientMonitor
	attestationsSubmitter                 eth2client.AttestationsSubmitter
	beaconBlockSubmitter                  eth2client.BeaconBlockSubmitter
	blindedBeaconBlockSubmitter           eth2client.BlindedBeaconBlockSubmitter
	beaconCommitteeSubscriptionsSubmitter eth2client.BeaconCommitteeSubscriptionsSubmitter
	aggregateAttestationsSubmitter        eth2client.AggregateAttestationsSubmitter
	proposalPreparationsSubmitter         eth2client.ProposalPreparationsSubmitter
	syncCommitteeMessagesSubmitter        eth2client.SyncCommitteeMessagesSubmitter
	syncCommitteeSubscriptionsSubmitter   eth2client.SyncCommitteeSubscriptionsSubmitter
	syncCommitteeContributionsSubmitter   eth2client.SyncCommitteeContributionsSubmitter
}

// module-wide log.
var log zerolog.Logger

// New creates a new submitter.
func New(_ context.Context, params ...Parameter) (*Service, error) {
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
		clientMonitor:                         parameters.clientMonitor,
		attestationsSubmitter:                 parameters.attestationsSubmitter,
		beaconBlockSubmitter:                  parameters.beaconBlockSubmitter,
		blindedBeaconBlockSubmitter:           parameters.blindedBeaconBlockSubmitter,
		beaconCommitteeSubscriptionsSubmitter: parameters.beaconCommitteeSubscriptionsSubmitter,
		aggregateAttestationsSubmitter:        parameters.aggregateAttestationsSubmitter,
		proposalPreparationsSubmitter:         parameters.proposalPreparationsSubmitter,
		syncCommitteeMessagesSubmitter:        parameters.syncCommitteeMessagesSubmitter,
		syncCommitteeSubscriptionsSubmitter:   parameters.syncCommitteeSubscriptionsSubmitter,
		syncCommitteeContributionsSubmitter:   parameters.syncCommitteeContributionsSubmitter,
	}

	return s, nil
}

// SubmitBeaconBlock submits a block.
func (s *Service) SubmitBeaconBlock(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
	if block == nil {
		return errors.New("no beacon block supplied")
	}

	started := time.Now()
	err := s.beaconBlockSubmitter.SubmitBeaconBlock(ctx, block)
	if service, isService := s.beaconBlockSubmitter.(eth2client.Service); isService {
		s.clientMonitor.ClientOperation(service.Address(), "submit beacon block", err == nil, time.Since(started))
	} else {
		s.clientMonitor.ClientOperation("<unknown>", "submit beacon block", err == nil, time.Since(started))
	}
	if err != nil {
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

// SubmitAttestations submits multiple attestations.
func (s *Service) SubmitAttestations(ctx context.Context, attestations []*phase0.Attestation) error {
	if len(attestations) == 0 {
		return errors.New("no attestations supplied")
	}

	started := time.Now()
	err := s.attestationsSubmitter.SubmitAttestations(ctx, attestations)
	if service, isService := s.attestationsSubmitter.(eth2client.Service); isService {
		s.clientMonitor.ClientOperation(service.Address(), "submit attestations", err == nil, time.Since(started))
	} else {
		s.clientMonitor.ClientOperation("<unknown>", "submit attestations", err == nil, time.Since(started))
	}
	if err != nil {
		return errors.Wrap(err, "failed to submit attestations")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(attestations)
		if err == nil {
			e.Str("attestations", string(data)).Msg("Submitted attestations")
		}
	}

	return nil
}

// SubmitBeaconCommitteeSubscriptions submits a batch of beacon committee subscriptions.
func (s *Service) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*apiv1.BeaconCommitteeSubscription) error {
	if len(subscriptions) == 0 {
		return errors.New("no beacon committee subscriptions supplied")
	}

	subs := make([]*apiv1.BeaconCommitteeSubscription, len(subscriptions))
	for i, subscription := range subscriptions {
		subs[i] = &apiv1.BeaconCommitteeSubscription{
			Slot:             subscription.Slot,
			CommitteeIndex:   subscription.CommitteeIndex,
			CommitteesAtSlot: subscription.CommitteesAtSlot,
			IsAggregator:     subscription.IsAggregator,
		}
	}
	started := time.Now()
	err := s.beaconCommitteeSubscriptionsSubmitter.SubmitBeaconCommitteeSubscriptions(ctx, subs)
	if service, isService := s.beaconCommitteeSubscriptionsSubmitter.(eth2client.Service); isService {
		s.clientMonitor.ClientOperation(service.Address(), "submit beacon committee subscription", err == nil, time.Since(started))
	} else {
		s.clientMonitor.ClientOperation("<unknown>", "submit beacon committee subscription", err == nil, time.Since(started))
	}
	if err != nil {
		return errors.Wrap(err, "failed to submit beacon committee subscriptions")
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
			e.Str("subscriptions", string(data)).Int("subscribing", len(subscriptions)).Int("aggregating", aggregating).Msg("Submitted subscriptions")
		}
	}

	return nil
}

// SubmitAggregateAttestations submits aggregate attestations.
func (s *Service) SubmitAggregateAttestations(ctx context.Context, aggregates []*phase0.SignedAggregateAndProof) error {
	if len(aggregates) == 0 {
		return errors.New("no aggregate attestations supplied")
	}

	started := time.Now()
	err := s.aggregateAttestationsSubmitter.SubmitAggregateAttestations(ctx, aggregates)
	if service, isService := s.aggregateAttestationsSubmitter.(eth2client.Service); isService {
		s.clientMonitor.ClientOperation(service.Address(), "submit aggregate attestation", err == nil, time.Since(started))
	} else {
		s.clientMonitor.ClientOperation("<unknown>", "submit aggregate attestation", err == nil, time.Since(started))
	}
	if err != nil {
		return errors.Wrap(err, "failed to submit aggregate attestation")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(aggregates)
		if err == nil {
			e.Str("attestation", string(data)).Msg("Submitted aggregate attestations")
		}
	}

	return nil
}

// SubmitProposalPreparations submits proposal preparations.
func (s *Service) SubmitProposalPreparations(ctx context.Context, preparations []*apiv1.ProposalPreparation) error {
	if len(preparations) == 0 {
		return errors.New("no proposal preparations supplied")
	}

	started := time.Now()
	err := s.proposalPreparationsSubmitter.SubmitProposalPreparations(ctx, preparations)
	if service, isService := s.proposalPreparationsSubmitter.(eth2client.Service); isService {
		s.clientMonitor.ClientOperation(service.Address(), "submit proposal preparations", err == nil, time.Since(started))
	} else {
		s.clientMonitor.ClientOperation("<unknown>", "submit proposal preparations", err == nil, time.Since(started))
	}
	if err != nil {
		return errors.Wrap(err, "failed to submit proposal preparations")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(preparations)
		if err == nil {
			e.Str("preparations", string(data)).Msg("Submitted proposal preparations")
		}
	}

	return nil
}

// SubmitSyncCommitteeMessages submits sync committee messages.
func (s *Service) SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
	if len(messages) == 0 {
		return errors.New("no sync committee messages supplied")
	}

	started := time.Now()
	err := s.syncCommitteeMessagesSubmitter.SubmitSyncCommitteeMessages(ctx, messages)
	if service, isService := s.aggregateAttestationsSubmitter.(eth2client.Service); isService {
		s.clientMonitor.ClientOperation(service.Address(), "submit sync committee messages", err == nil, time.Since(started))
	} else {
		s.clientMonitor.ClientOperation("<unknown>", "submit sync committee messages", err == nil, time.Since(started))
	}
	if err != nil {
		return errors.Wrap(err, "failed to submit sync committee messages")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(messages)
		if err == nil {
			e.Str("messages", string(data)).Msg("Submitted sync committee messages")
		}
	}

	return nil
}

// SubmitSyncCommitteeSubscriptions submits a batch of beacon committee subscriptions.
func (s *Service) SubmitSyncCommitteeSubscriptions(ctx context.Context, subscriptions []*apiv1.SyncCommitteeSubscription) error {
	if len(subscriptions) == 0 {
		return errors.New("no sync committee subscriptions supplied")
	}

	started := time.Now()
	err := s.syncCommitteeSubscriptionsSubmitter.SubmitSyncCommitteeSubscriptions(ctx, subscriptions)
	if service, isService := s.syncCommitteeSubscriptionsSubmitter.(eth2client.Service); isService {
		s.clientMonitor.ClientOperation(service.Address(), "submit sync committee subscription", err == nil, time.Since(started))
	} else {
		s.clientMonitor.ClientOperation("<unknown>", "submit sync committee subscription", err == nil, time.Since(started))
	}
	if err != nil {
		return errors.Wrap(err, "failed to submit sync committee subscriptions")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(subscriptions)
		if err == nil {
			e.Str("subscriptions", string(data)).Int("subscribing", len(subscriptions)).Msg("Submitted subscriptions")
		}
	}

	return nil
}

// SubmitSyncCommitteeContributions submits sync committee contributions.
func (s *Service) SubmitSyncCommitteeContributions(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error {
	if len(contributionAndProofs) == 0 {
		return errors.New("no sync committee contribution and proofs supplied")
	}

	started := time.Now()
	err := s.syncCommitteeContributionsSubmitter.SubmitSyncCommitteeContributions(ctx, contributionAndProofs)
	if service, isService := s.syncCommitteeContributionsSubmitter.(eth2client.Service); isService {
		s.clientMonitor.ClientOperation(service.Address(), "submit sync committee contribution and proofs", err == nil, time.Since(started))
	} else {
		s.clientMonitor.ClientOperation("<unknown>", "submit sync committee contribution and proofs", err == nil, time.Since(started))
	}
	if err != nil {
		return errors.Wrap(err, "failed to submit sync committee contribution and proofs")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(contributionAndProofs)
		if err == nil {
			e.Str("contribution_and_proofs", string(data)).Msg("Submitted contribution and proofs")
		}
	}

	return nil
}
