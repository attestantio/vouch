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
	"strings"
	"sync"
	"time"

	restdaemon "github.com/attestantio/go-block-relay/services/daemon/rest"
	"github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/blockrelay"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/wealdtech/go-majordomo"
)

// Service is the builder service for Vouch.
type Service struct {
	monitor                     metrics.Service
	majordomo                   majordomo.Service
	chainTime                   chaintime.Service
	configBaseURL               string
	validatingAccountsProvider  accountmanager.ValidatingAccountsProvider
	validatorRegistrationSigner signer.ValidatorRegistrationSigner
	builderBidsCache            map[string]map[string]*spec.VersionedSignedBuilderBid
	builderBidsCacheMu          sync.RWMutex
	timeout                     time.Duration

	boostConfig   *blockrelay.BoostConfig
	boostConfigMu sync.RWMutex
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

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}

	s := &Service{
		monitor:                     parameters.monitor,
		majordomo:                   parameters.majordomo,
		chainTime:                   parameters.chainTime,
		configBaseURL:               parameters.configBaseURL,
		validatingAccountsProvider:  parameters.validatingAccountsProvider,
		validatorRegistrationSigner: parameters.validatorRegistrationSigner,
		timeout:                     parameters.timeout,
		builderBidsCache:            make(map[string]map[string]*spec.VersionedSignedBuilderBid),
	}

	// Remove trailing / from base URL.
	s.configBaseURL = strings.TrimSuffix(s.configBaseURL, "/")

	// Carry out initial fetch of proposer configuration.
	// Run this in a goroutine as it can take a while to complete, and we don't want to miss attestations
	// in the meantime.
	go func(ctx context.Context) {
		s.fetchBoostConfig(ctx, nil)

		if s.boostConfig == nil {
			log.Error().Msg("Failed to obtain boost configuration, will retry but blocks cannot be proposed in the meantime")
		} else {
			// Carry out initial submission of validator registrations.
			s.submitValidatorRegistrations(ctx, nil)
		}
	}(ctx)

	// Periodically fetch the proposer configuration.
	if err := parameters.scheduler.SchedulePeriodicJob(ctx,
		"blockrelay",
		"Fetch proposer configuration",
		s.fetchBoostConfigRuntime,
		nil,
		s.fetchBoostConfig,
		nil,
	); err != nil {
		return nil, errors.Wrap(err, "failed to start proposer config fetcher")
	}

	// Periodically submit the validator registrations.
	if err := parameters.scheduler.SchedulePeriodicJob(ctx,
		"blockrelay",
		"Submit validator registrations",
		s.submitValidatorRegistrationsRuntime,
		nil,
		s.submitValidatorRegistrations,
		nil,
	); err != nil {
		return nil, errors.Wrap(err, "failed to start validator registration submitter")
	}

	// Create the API daemon.
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
		return nil, errors.Wrap(err, "failed to create REST API daemon")
	}

	return s, nil
}
