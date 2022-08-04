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
	builderclient "github.com/attestantio/go-builder-client"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                        zerolog.Level
	monitor                         metrics.Service
	name                            string
	gasLimit                        uint64
	validatorRegistrationSigner     signer.ValidatorRegistrationSigner
	validatorRegistrationsSubmitter builderclient.ValidatorRegistrationsSubmitter
	builderBidProvider              builderclient.BuilderBidProvider
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

// WithName sets the name for the module.
func WithName(name string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.name = name
	})
}

// WithGasLimit sets the gas limit for the module.
func WithGasLimit(gasLimit uint64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.gasLimit = gasLimit
	})
}

// WithValidatorRegistrationsigner sets the validator registration signer.
func WithValidatorRegistrationsigner(signer signer.ValidatorRegistrationSigner) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatorRegistrationSigner = signer
	})
}

// WithValidatorRegistrationsSubmitter sets the validator registrations submitter.
func WithValidatorRegistrationsSubmitter(submitter builderclient.ValidatorRegistrationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatorRegistrationsSubmitter = submitter
	})
}

// WithBuilderBidProvider sets the execution payload header provider.
func WithBuilderBidProvider(provider builderclient.BuilderBidProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.builderBidProvider = provider
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
	if parameters.name == "" {
		return nil, errors.New("no name specified")
	}
	if parameters.gasLimit == 0 {
		return nil, errors.New("no gas limit specified")
	}
	if parameters.validatorRegistrationSigner == nil {
		return nil, errors.New("no validator registration signer specified")
	}
	if parameters.validatorRegistrationsSubmitter == nil {
		return nil, errors.New("no validator registrations submitter specified")
	}
	if parameters.builderBidProvider == nil {
		return nil, errors.New("no builder bid provider specified")
	}

	return &parameters, nil
}
