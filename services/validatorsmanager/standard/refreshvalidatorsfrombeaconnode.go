// Copyright © 2024 Attestant Limited.
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

package standard

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
)

// RefreshValidatorsFromBeaconNode refreshes the local store from the beacon node.
// This is an expensive operation, and should not be called in the validating path.
func (s *Service) RefreshValidatorsFromBeaconNode(ctx context.Context, pubKeys []phase0.BLSPubKey) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.validatorsmanager.standard").Start(ctx, "RefreshValidatorsFromBeaconNode")
	defer span.End()

	started := time.Now()
	validatorsResponse, err := s.validatorsProvider.Validators(ctx, &api.ValidatorsOpts{
		State:   "head",
		PubKeys: pubKeys,
	})
	if service, isService := s.validatorsProvider.(eth2client.Service); isService {
		s.clientMonitor.ClientOperation(service.Address(), "validators", err == nil, time.Since(started))
	} else {
		s.clientMonitor.ClientOperation("<unknown>", "validators", err == nil, time.Since(started))
	}
	if err != nil {
		return errors.Wrap(err, "failed to obtain validators")
	}
	validators := validatorsResponse.Data
	s.log.Trace().Dur("elapsed", time.Since(started)).Int("received", len(validators)).Msg("Received validators from beacon node")

	// If we have no validators at this point we leave early rather than possibly replace existing information.
	if len(validators) == 0 {
		s.log.Trace().Msg("No validators received; not replacing existing validators")
		return nil
	}

	validatorsByIndex := make(map[phase0.ValidatorIndex]*phase0.Validator)
	validatorsByPubKey := make(map[phase0.BLSPubKey]*phase0.Validator)
	validatorPubKeyToIndex := make(map[phase0.BLSPubKey]phase0.ValidatorIndex)
	for _, validator := range validators {
		validatorsByIndex[validator.Index] = validator.Validator
		validatorsByPubKey[validator.Validator.PublicKey] = validator.Validator
		validatorPubKeyToIndex[validator.Validator.PublicKey] = validator.Index
	}
	s.log.Trace().
		Int("validators_by_index", len(validatorsByIndex)).
		Int("validators_by_pubkey", len(validatorsByPubKey)).
		Int("validator_pubkey_to_index", len(validatorPubKeyToIndex)).
		Msg("Updating validator cache")

	s.validatorsMutex.Lock()
	s.validatorsByIndex = validatorsByIndex
	s.validatorsByPubKey = validatorsByPubKey
	s.validatorPubKeyToIndex = validatorPubKeyToIndex
	s.validatorsMutex.Unlock()

	return nil
}
