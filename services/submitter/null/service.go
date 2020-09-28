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

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/submitter"
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
func (s *Service) SubmitBeaconBlock(ctx context.Context, block *spec.SignedBeaconBlock) error {
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

// SubmitAttestation submits a beacon block attestation.
func (s *Service) SubmitAttestation(ctx context.Context, attestation *spec.Attestation) error {
	if attestation == nil {
		return errors.New("no attestation supplied")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(attestation)
		if err == nil {
			e.Str("attestation", string(data)).Msg("Not submitting attestation")
		}
	}

	return nil
}

// SubmitBeaconCommitteeSubscriptions submits a batch of beacon committee subscriptions.
func (s *Service) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*submitter.BeaconCommitteeSubscription) error {
	if subscriptions == nil {
		return errors.New("no subscriptions supplied")
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
			e.Str("subscriptions", string(data)).Int("subscribing", len(subscriptions)).Int("aggregating", aggregating).Msg("Not submitting subscriptions")
		}
	}

	return nil
}

// SubmitAggregateAttestation submits an aggregate attestation.
func (s *Service) SubmitAggregateAttestation(ctx context.Context, aggregate *spec.SignedAggregateAndProof) error {
	if aggregate == nil {
		return errors.New("no aggregate attestation supplied")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(aggregate)
		if err == nil {
			e.Str("attestation", string(data)).Msg("Not submitting aggregate attestation")
		}
	}

	return nil
}
