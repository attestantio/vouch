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
	"time"

	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/attestantio/vouch/services/signer"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/wealdtech/go-majordomo"
)

type parameters struct {
	logLevel                    zerolog.Level
	monitor                     metrics.Service
	majordomo                   majordomo.Service
	scheduler                   scheduler.Service
	serverName                  string
	listenAddress               string
	chainTime                   chaintime.Service
	configBaseURL               string
	validatingAccountsProvider  accountmanager.ValidatingAccountsProvider
	validatorRegistrationSigner signer.ValidatorRegistrationSigner
	timeout                     time.Duration
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(*parameters)
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

// WithServerName sets the server name for the HTTP REST daemon.
func WithServerName(serverName string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.serverName = serverName
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

// WithConfigBaseURL sets the base URL for the config server.
func WithConfigBaseURL(url string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.configBaseURL = url
	})
}

// WithValidatingAccountsProvider sets the account manager.
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

// WithTimeout sets the timeout for requests.
func WithTimeout(timeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.timeout = timeout
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
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
	if parameters.serverName == "" {
		return nil, errors.New("no server name specified")
	}
	if parameters.listenAddress == "" {
		return nil, errors.New("no listen address specified")
	}
	if parameters.chainTime == nil {
		return nil, errors.New("no chaintime specified")
	}
	if parameters.configBaseURL == "" {
		return nil, errors.New("no configuration base URL specified")
	}
	if parameters.validatingAccountsProvider == nil {
		return nil, errors.New("no validating accounts provider specified")
	}
	if parameters.validatorRegistrationSigner == nil {
		return nil, errors.New("no validator registration signer specified")
	}
	if parameters.timeout == 0 {
		return nil, errors.New("no timeout specified")
	}

	return &parameters, nil
}
