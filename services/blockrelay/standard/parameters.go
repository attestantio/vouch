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
	builderclient "github.com/attestantio/go-builder-client"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                         zerolog.Level
	monitor                          metrics.Service
	serverName                       string
	listenAddress                    string
	validatorRegistrationsSubmitters []builderclient.ValidatorRegistrationsSubmitter
	builderBidProviders              []builderclient.BuilderBidProvider
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

// WithValidatorRegistrationsSubmitters sets submitters to which to send validator registrations.
func WithValidatorRegistrationsSubmitters(submitters []builderclient.ValidatorRegistrationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatorRegistrationsSubmitters = submitters
	})
}

// WithBuilderBidProviders sets the providers from which to obtain builder bids.
func WithBuilderBidProviders(providers []builderclient.BuilderBidProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.builderBidProviders = providers
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
	if parameters.serverName == "" {
		return nil, errors.New("no server name specified")
	}
	if parameters.listenAddress == "" {
		return nil, errors.New("no listen address specified")
	}
	if parameters.validatorRegistrationsSubmitters == nil {
		return nil, errors.New("no validator registrations submitters specified")
	}
	if parameters.builderBidProviders == nil {
		return nil, errors.New("no builder bid providers specified")
	}

	return &parameters, nil
}
