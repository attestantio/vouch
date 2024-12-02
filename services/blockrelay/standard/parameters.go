// Copyright © 2022, 2023 Attestant Limited.
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
	"bytes"
	"net"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/blockrelay"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/strategies/builderbid"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/wealdtech/go-majordomo"
)

type parameters struct {
	logLevel                                  zerolog.Level
	monitor                                   metrics.Service
	majordomo                                 majordomo.Service
	scheduler                                 scheduler.Service
	listenAddress                             string
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
	secondaryValidatorRegistrationsSubmitters []consensusclient.ValidatorRegistrationsSubmitter
	logResults                                bool
	releaseVersion                            string
	builderBidProvider                        builderbid.Provider
	builderConfigs                            map[phase0.BLSPubKey]*blockrelay.BuilderConfig
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(p *parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(p *parameters) {
	f(p)
}

// WithLogLevel sets the log level for the module.
func WithLogLevel(logLevel zerolog.Level) Parameter {
	return parameterFunc(func(p *parameters) {
		p.logLevel = logLevel
	})
}

// WithMonitor sets the monitor for the module.
func WithMonitor(monitor metrics.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithMajordomo sets majordomo for the module.
func WithMajordomo(majordomo majordomo.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.majordomo = majordomo
	})
}

// WithScheduler provides the scheduler service.
func WithScheduler(scheduler scheduler.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.scheduler = scheduler
	})
}

// WithListenAddress sets the listen address for the module.
func WithListenAddress(address string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.listenAddress = address
	})
}

// WithChainTime sets the chaintime service.
func WithChainTime(service chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTime = service
	})
}

// WithConfigURL sets the URL for the config server.
func WithConfigURL(url string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.configURL = url
	})
}

// WithFallbackFeeRecipient sets the fallback fee recipient for all validators.
func WithFallbackFeeRecipient(feeRecipient bellatrix.ExecutionAddress) Parameter {
	return parameterFunc(func(p *parameters) {
		p.fallbackFeeRecipient = feeRecipient
	})
}

// WithFallbackGasLimit sets the fallback gas limit for all validators.
func WithFallbackGasLimit(gasLimit uint64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.fallbackGasLimit = gasLimit
	})
}

// WithClientCertURL sets the URL for the client certificate when carrying out dynamic requests.
func WithClientCertURL(url string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientCertURL = url
	})
}

// WithClientKeyURL sets the URL for the client key when carrying out dynamic requests.
func WithClientKeyURL(url string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientKeyURL = url
	})
}

// WithCACertURL sets the URL for the CA certificate when carrying out dynamic requests.
func WithCACertURL(url string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.caCertURL = url
	})
}

// WithAccountsProvider sets the accounts provider.
func WithAccountsProvider(provider accountmanager.AccountsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.accountsProvider = provider
	})
}

// WithValidatorsProvider sets the validators provider.
func WithValidatorsProvider(provider consensusclient.ValidatorsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatorsProvider = provider
	})
}

// WithValidatingAccountsProvider sets the validating accounts provider.
func WithValidatingAccountsProvider(provider accountmanager.ValidatingAccountsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatingAccountsProvider = provider
	})
}

// WithValidatorRegistrationSigner sets the validator registration signer.
func WithValidatorRegistrationSigner(signer signer.ValidatorRegistrationSigner) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatorRegistrationSigner = signer
	})
}

// WithSecondaryValidatorRegistrationsSubmitters sets the secondary validator registrations submitters.
func WithSecondaryValidatorRegistrationsSubmitters(submitters []consensusclient.ValidatorRegistrationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.secondaryValidatorRegistrationsSubmitters = submitters
	})
}

// WithLogResults sets the flag to log relay results.
func WithLogResults(logResults bool) Parameter {
	return parameterFunc(func(p *parameters) {
		p.logResults = logResults
	})
}

// WithReleaseVersion sets the release version for Vouch.
func WithReleaseVersion(version string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.releaseVersion = version
	})
}

// WithBuilderBidProvider sets builder bid provider.
func WithBuilderBidProvider(provider builderbid.Provider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.builderBidProvider = provider
	})
}

// WithBuilderConfigs are the builder configurations.
func WithBuilderConfigs(builderConfigs map[phase0.BLSPubKey]*blockrelay.BuilderConfig) Parameter {
	return parameterFunc(func(p *parameters) {
		p.builderConfigs = builderConfigs
	})
}

// zeroExecutionAddress is used for comparison purposes.
var zeroExecutionAddress bellatrix.ExecutionAddress

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:       zerolog.GlobalLevel(),
		builderConfigs: map[phase0.BLSPubKey]*blockrelay.BuilderConfig{},
	}
	for _, p := range params {
		p.apply(&parameters)
	}

	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.majordomo == nil {
		return nil, errors.New("no majordomo specified")
	}
	if parameters.scheduler == nil {
		return nil, errors.New("no scheduler specified")
	}
	if parameters.chainTime == nil {
		return nil, errors.New("no chaintime specified")
	}
	if bytes.Equal(parameters.fallbackFeeRecipient[:], zeroExecutionAddress[:]) {
		return nil, errors.New("no fallback fee recipient specified")
	}
	if parameters.fallbackGasLimit == 0 {
		return nil, errors.New("no fallback gas limit specified")
	}
	if parameters.accountsProvider == nil {
		return nil, errors.New("no accounts provider specified")
	}
	if parameters.validatorsProvider == nil {
		return nil, errors.New("no validators provider specified")
	}
	if parameters.validatingAccountsProvider == nil {
		return nil, errors.New("no validating accounts provider specified")
	}
	if parameters.validatorRegistrationSigner == nil {
		return nil, errors.New("no validator registration signer specified")
	}
	if parameters.listenAddress == "" {
		return nil, errors.New("no listen address specified")
	}
	if _, _, err := net.SplitHostPort(parameters.listenAddress); err != nil {
		return nil, errors.New("listen address malformed")
	}
	// config URL can be empty.
	if parameters.releaseVersion == "" {
		return nil, errors.New("no release version specified")
	}
	if parameters.builderBidProvider == nil {
		return nil, errors.New("no builder bid provider specified")
	}
	if parameters.builderConfigs == nil {
		return nil, errors.New("no builder configs specified")
	}

	return &parameters, nil
}
