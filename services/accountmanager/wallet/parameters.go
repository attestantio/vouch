// Copyright © 2024 Attestant Limited.
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

package wallet

import (
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/validatorsmanager"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel               zerolog.Level
	monitor                metrics.Service
	processConcurrency     int64
	locations              []string
	accountPaths           []string
	passphrases            [][]byte
	validatorsManager      validatorsmanager.Service
	specProvider           eth2client.SpecProvider
	domainProvider         eth2client.DomainProvider
	farFutureEpochProvider eth2client.FarFutureEpochProvider
	currentEpochProvider   chaintime.Service
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

// WithProcessConcurrency sets the concurrency for the service.
func WithProcessConcurrency(concurrency int64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.processConcurrency = concurrency
	})
}

// WithLocations sets the locations to look for wallets.
func WithLocations(locations []string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.locations = locations
	})
}

// WithAccountPaths sets the accounts paths for which to validate.
func WithAccountPaths(accountPaths []string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.accountPaths = accountPaths
	})
}

// WithPassphrases sets the passphrases to unlock accounts.
func WithPassphrases(passphrases [][]byte) Parameter {
	return parameterFunc(func(p *parameters) {
		p.passphrases = passphrases
	})
}

// WithValidatorsManager sets the validator manager.
func WithValidatorsManager(manager validatorsmanager.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatorsManager = manager
	})
}

// WithSpecProvider sets the specification provider.
func WithSpecProvider(provider eth2client.SpecProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.specProvider = provider
	})
}

// WithFarFutureEpochProvider sets the far future epoch provider.
func WithFarFutureEpochProvider(provider eth2client.FarFutureEpochProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.farFutureEpochProvider = provider
	})
}

// WithDomainProvider sets the domain provider.
func WithDomainProvider(provider eth2client.DomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.domainProvider = provider
	})
}

// WithCurrentEpochProvider sets the current epoch provider.
func WithCurrentEpochProvider(provider chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.currentEpochProvider = provider
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.processConcurrency == 0 {
		return nil, errors.New("no process concurrency specified")
	}
	if parameters.accountPaths == nil {
		return nil, errors.New("no account paths specified")
	}
	if len(parameters.passphrases) == 0 {
		return nil, errors.New("no passphrases specified")
	}
	if parameters.validatorsManager == nil {
		return nil, errors.New("no validators manager specified")
	}
	if parameters.specProvider == nil {
		return nil, errors.New("no spec provider specified")
	}
	if parameters.farFutureEpochProvider == nil {
		return nil, errors.New("no far future epoch provider specified")
	}
	if parameters.domainProvider == nil {
		return nil, errors.New("no domain provider specified")
	}
	if parameters.currentEpochProvider == nil {
		return nil, errors.New("no current epoch provider specified")
	}

	return &parameters, nil
}
