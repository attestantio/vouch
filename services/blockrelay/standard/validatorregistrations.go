// Copyright © 2022, 2024 Attestant Limited.
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

	"github.com/attestantio/go-block-relay/types"
	builderapi "github.com/attestantio/go-builder-client/api"
	builderapiv1 "github.com/attestantio/go-builder-client/api/v1"
	builderspec "github.com/attestantio/go-builder-client/spec"
	"go.opentelemetry.io/otel"
)

func (s *Service) ValidatorRegistrations(ctx context.Context,
	registrations []*types.SignedValidatorRegistration,
) (
	[]string,
	error,
) {
	_, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "ValidatorRegistrations")
	defer span.End()

	s.controlledValidatorsMu.RLock()
	controlledValidators := s.controlledValidators
	s.controlledValidatorsMu.RUnlock()

	relayRegistrations := make(map[string][]*builderapi.VersionedSignedValidatorRegistration)
	for _, registration := range registrations {
		if _, exists := controlledValidators[registration.Message.Pubkey]; exists {
			log.Trace().Stringer("pubkey", registration.Message.Pubkey).Msg("Validator controlled by Vouch; not forwarding registration")
			continue
		}
		log.Trace().Stringer("pubkey", registration.Message.Pubkey).Msg("Validator not controlled by Vouch; forwarding registration")

		proposerConfig, err := s.ProposerConfig(ctx, nil, registration.Message.Pubkey)
		if err != nil {
			log.Warn().Err(err).Stringer("pubkey", registration.Message.Pubkey).Msg("Failed to obtain execution configuration for validator; skipping")
			continue
		}

		// Obtain the nodes to which we forward the registration.
		for _, relay := range proposerConfig.Relays {
			// Add the registration to the list for the relay.
			if _, exists := relayRegistrations[relay.Address]; !exists {
				relayRegistrations[relay.Address] = make([]*builderapi.VersionedSignedValidatorRegistration, 0)
			}
			relayRegistrations[relay.Address] = append(relayRegistrations[relay.Address], &builderapi.VersionedSignedValidatorRegistration{
				Version: builderspec.BuilderVersionV1,
				V1: &builderapiv1.SignedValidatorRegistration{
					Message: &builderapiv1.ValidatorRegistration{
						FeeRecipient: registration.Message.FeeRecipient,
						GasLimit:     registration.Message.GasLimit,
						Timestamp:    registration.Message.Timestamp,
						Pubkey:       registration.Message.Pubkey,
					},
					Signature: registration.Signature,
				},
			})
		}
	}
	s.submitRelayRegistrations(ctx, relayRegistrations)

	return nil, nil
}
