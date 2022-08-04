// Copyright © 2022 Attestant Limited.
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

package mevboost

import (
	"context"

	builderclient "github.com/attestantio/go-builder-client"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the builder service for Vouch.
type Service struct {
	monitor                         metrics.Service
	name                            string
	validatorRegistrationSigner     signer.ValidatorRegistrationSigner
	validatorRegistrationsSubmitter builderclient.ValidatorRegistrationsSubmitter
	builderBidProvider              builderclient.BuilderBidProvider
	gasLimit                        uint64
}

// module-wide log.
var log zerolog.Logger

// New creates a new controller.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "builder").Str("impl", "mevboost").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		monitor:                         parameters.monitor,
		name:                            parameters.name,
		gasLimit:                        parameters.gasLimit,
		validatorRegistrationSigner:     parameters.validatorRegistrationSigner,
		validatorRegistrationsSubmitter: parameters.validatorRegistrationsSubmitter,
		builderBidProvider:              parameters.builderBidProvider,
	}

	return s, nil
}

// Name returns the name of the builder.
func (s *Service) Name() string {
	return s.name
}
