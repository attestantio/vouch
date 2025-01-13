// Copyright © 2022 - 2024 Attestant Limited.
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
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	builderspec "github.com/attestantio/go-builder-client/spec"
	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/blockrelay"
	v2 "github.com/attestantio/vouch/services/blockrelay/v2"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/strategies/builderbid"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/wealdtech/go-majordomo"
	"golang.org/x/sync/semaphore"
)

// Service is the builder service for Vouch.
type Service struct {
	log                                       zerolog.Logger
	monitor                                   metrics.Service
	majordomo                                 majordomo.Service
	chainTime                                 chaintime.Service
	configURL                                 string
	fallbackFeeRecipient                      bellatrix.ExecutionAddress
	fallbackGasLimit                          uint64
	clientCertURL                             string
	clientKeyURL                              string
	caCertURL                                 string
	accountsProvider                          accountmanager.AccountsProvider
	validatorsProvider                        consensusclient.ValidatorsProvider
	validatingAccountsProvider                accountmanager.ValidatingAccountsProvider
	validatorRegistrationSigner               signer.ValidatorRegistrationSigner
	builderBidsCache                          map[string]map[string]*builderspec.VersionedSignedBuilderBid
	builderBidsCacheMu                        sync.RWMutex
	latestValidatorRegistrations              map[phase0.BLSPubKey]phase0.Root
	latestValidatorRegistrationsMu            sync.RWMutex
	signedValidatorRegistrations              map[phase0.Root]*apiv1.SignedValidatorRegistration
	signedValidatorRegistrationsMu            sync.RWMutex
	secondaryValidatorRegistrationsSubmitters []consensusclient.ValidatorRegistrationsSubmitter
	logResults                                bool
	releaseVersion                            string
	builderBidProvider                        builderbid.Provider
	builderConfigs                            map[phase0.BLSPubKey]*blockrelay.BuilderConfig

	// builderBidMu ensures that only one builder bid operation is actively talking to
	// relays at a time.
	builderBidMu sync.Mutex

	executionConfig   blockrelay.ExecutionConfigurator
	executionConfigMu sync.RWMutex

	// controlledValidators is a map of validators that are controlled
	// by Vouch.  Used when receiving registrations from beacon nodes to know
	// which registrations to forward, and which to drop because we have already
	// submitted them.
	controlledValidators   map[phase0.BLSPubKey]struct{}
	controlledValidatorsMu sync.RWMutex

	activitySem *semaphore.Weighted

	// Needed only to create dummy VersionedSignedBuilderBid in cacheBid.
	electraForkEpoch phase0.Epoch
}

// New creates a new controller.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "blockrelay").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}
	electraForkEpoch := parameters.chainTime.HardForkEpoch(ctx, "ELECTRA_FORK_EPOCH")

	s := &Service{
		log:                          log,
		monitor:                      parameters.monitor,
		majordomo:                    parameters.majordomo,
		chainTime:                    parameters.chainTime,
		configURL:                    parameters.configURL,
		clientCertURL:                parameters.clientCertURL,
		clientKeyURL:                 parameters.clientKeyURL,
		caCertURL:                    parameters.caCertURL,
		fallbackFeeRecipient:         parameters.fallbackFeeRecipient,
		fallbackGasLimit:             parameters.fallbackGasLimit,
		accountsProvider:             parameters.accountsProvider,
		validatorsProvider:           parameters.validatorsProvider,
		validatingAccountsProvider:   parameters.validatingAccountsProvider,
		validatorRegistrationSigner:  parameters.validatorRegistrationSigner,
		latestValidatorRegistrations: make(map[phase0.BLSPubKey]phase0.Root),
		signedValidatorRegistrations: make(map[phase0.Root]*apiv1.SignedValidatorRegistration),
		secondaryValidatorRegistrationsSubmitters: parameters.secondaryValidatorRegistrationsSubmitters,
		logResults:           parameters.logResults,
		releaseVersion:       parameters.releaseVersion,
		builderBidsCache:     make(map[string]map[string]*builderspec.VersionedSignedBuilderBid),
		executionConfig:      &v2.ExecutionConfig{Version: 2},
		activitySem:          semaphore.NewWeighted(1),
		builderBidProvider:   parameters.builderBidProvider,
		builderConfigs:       parameters.builderConfigs,
		controlledValidators: make(map[phase0.BLSPubKey]struct{}),
		electraForkEpoch:     electraForkEpoch,
	}

	// Carry out initial fetch of execution configuration.
	// Need to run this inline, as other modules need this information.
	s.fetchExecutionConfig(ctx)
	// Carry out initial submission of validator registrations.
	// Can run this in a separate goroutine to avoid blocking.
	go func(ctx context.Context) {
		s.submitValidatorRegistrations(ctx)
	}(ctx)

	// Periodically fetch the execution configuration.
	if err := parameters.scheduler.SchedulePeriodicJob(ctx,
		"Fetch execution configuration",
		"Fetch execution configuration",
		s.fetchExecutionConfigRuntime,
		s.fetchExecutionConfig,
	); err != nil {
		return nil, errors.Wrap(err, "failed to start execution config fetcher")
	}

	// Periodically submit the validator registrations.
	if err := parameters.scheduler.SchedulePeriodicJob(ctx,
		"blockrelay",
		"Submit validator registrations",
		s.submitValidatorRegistrationsRuntime,
		s.submitValidatorRegistrations,
	); err != nil {
		return nil, errors.Wrap(err, "failed to start validator registration submitter")
	}

	// Create the API daemon.
	_, err = restdaemon.New(ctx,
		restdaemon.WithLogLevel(parameters.logLevel),
		restdaemon.WithMonitor(parameters.monitor),
		restdaemon.WithListenAddress(parameters.listenAddress),
		restdaemon.WithValidatorRegistrar(s),
		restdaemon.WithBlockAuctioneer(s),
		restdaemon.WithBlockUnblinder(s),
		restdaemon.WithBuilderBidProvider(s),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create REST API daemon")
	}

	return s, nil
}
