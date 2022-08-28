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
	"errors"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/blockrelay"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                        zerolog.Level
	monitor                         metrics.Service
	chainTimeService                chaintime.Service
	validatingAccountsProvider      accountmanager.ValidatingAccountsProvider
	proposalPreparationsSubmitter   eth2client.ProposalPreparationsSubmitter
	executionConfigProvider         blockrelay.ExecutionConfigProvider
	validatorRegistrationsSubmitter blockrelay.ValidatorRegistrationsSubmitter
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

// WithChainTimeService sets the chaintime service.
func WithChainTimeService(service chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTimeService = service
	})
}

// WithMonitor sets the monitor for this module.
func WithMonitor(monitor metrics.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithValidatingAccountsProvider sets the account manager.
func WithValidatingAccountsProvider(provider accountmanager.ValidatingAccountsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatingAccountsProvider = provider
	})
}

// WithProposalPreparationsSubmitter sets the proposal preparations submitter.
func WithProposalPreparationsSubmitter(submitter eth2client.ProposalPreparationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.proposalPreparationsSubmitter = submitter
	})
}

// WithExecutionConfigProvider sets the execution configuration provider.
func WithExecutionConfigProvider(provider blockrelay.ExecutionConfigProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.executionConfigProvider = provider
	})
}

// WithValidatorRegistrationsSubmitter sets the validator registrations submitter.
func WithValidatorRegistrationsSubmitter(submitter blockrelay.ValidatorRegistrationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatorRegistrationsSubmitter = submitter
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
		monitor:  nullmetrics.New(context.Background()),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.chainTimeService == nil {
		return nil, errors.New("no chain time service specified")
	}
	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.validatingAccountsProvider == nil {
		return nil, errors.New("no validating accounts provider specified")
	}
	if parameters.proposalPreparationsSubmitter == nil {
		return nil, errors.New("no proposal preparations submitter specified")
	}
	if parameters.executionConfigProvider == nil {
		return nil, errors.New("no execution configuration provider specified")
	}

	return &parameters, nil
}
