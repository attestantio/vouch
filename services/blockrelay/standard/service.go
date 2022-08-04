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

package standard

import (
	"context"
	"sync"

	restdaemon "github.com/attestantio/go-block-relay/services/daemon/rest"
	builderclient "github.com/attestantio/go-builder-client"
	"github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the builder service for Vouch.
type Service struct {
	monitor                          metrics.Service
	gasLimit                         uint64
	validatorRegistrationSigner      signer.ValidatorRegistrationSigner
	validatorRegistrationsSubmitters []builderclient.ValidatorRegistrationsSubmitter
	builderBidProviders              []builderclient.BuilderBidProvider
	builderBidsCache                 map[string]map[string]*spec.VersionedSignedBuilderBid
	builderBidsCacheMu               sync.RWMutex
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
	log = zerologger.With().Str("service", "blockrelay").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		monitor:                          parameters.monitor,
		gasLimit:                         parameters.gasLimit,
		validatorRegistrationSigner:      parameters.validatorRegistrationSigner,
		validatorRegistrationsSubmitters: parameters.validatorRegistrationsSubmitters,
		builderBidProviders:              parameters.builderBidProviders,
		builderBidsCache:                 make(map[string]map[string]*spec.VersionedSignedBuilderBid),
	}

	// Create the daemon.
	_, err = restdaemon.New(ctx,
		restdaemon.WithLogLevel(parameters.logLevel),
		restdaemon.WithMonitor(parameters.monitor),
		restdaemon.WithServerName(parameters.serverName),
		restdaemon.WithListenAddress(parameters.listenAddress),
		restdaemon.WithValidatorRegistrar(s),
		restdaemon.WithBlockAuctioneer(s),
		restdaemon.WithBuilderBidProvider(s),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create REST daemon")
	}

	return s, nil
}
