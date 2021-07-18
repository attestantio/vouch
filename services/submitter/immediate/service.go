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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
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
		clientMonitor:                         parameters.clientMonitor,
		attestationsSubmitter:                 parameters.attestationsSubmitter,
		beaconBlockSubmitter:                  parameters.beaconBlockSubmitter,
		beaconCommitteeSubscriptionsSubmitter: parameters.beaconCommitteeSubscriptionsSubmitter,
		aggregateAttestationsSubmitter:        parameters.aggregateAttestationsSubmitter,
	}

	return s, nil
}

// SubmitBeaconBlock submits a block.
func (s *Service) SubmitBeaconBlock(ctx context.Context, block *phase0.SignedBeaconBlock) error {
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
func (s *Service) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*api.BeaconCommitteeSubscription) error {
	if len(subscriptions) == 0 {
		return errors.New("no beacon committee subscriptions supplied")
	}

	subs := make([]*api.BeaconCommitteeSubscription, len(subscriptions))
	for i, subscription := range subscriptions {
		subs[i] = &api.BeaconCommitteeSubscription{
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
