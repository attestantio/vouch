// Copyright © 2020 - 2026 Attestant Limited.
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

package dirk

import (
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/validatorsmanager"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	majordomo "github.com/wealdtech/go-majordomo"
)

type parameters struct {
	logLevel               zerolog.Level
	monitor                metrics.Service
	timeout                time.Duration
	clientMonitor          metrics.ClientMonitor
	processConcurrency     int64
	endpoints              []string
	accountPaths           []string
	majordomo              majordomo.Service
	clientCertURI          string
	clientKeyURI           string
	caCertURI              string
	domainProvider         eth2client.DomainProvider
	validatorsManager      validatorsmanager.Service
	farFutureEpochProvider eth2client.FarFutureEpochProvider
	currentEpochProvider   chaintime.Service
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

// WithTimeout sets the timeout for the module.
func WithTimeout(timeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.timeout = timeout
	})
}

// WithClientMonitor sets the client monitor for the module.
func WithClientMonitor(clientMonitor metrics.ClientMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientMonitor = clientMonitor
	})
}

// WithProcessConcurrency sets the concurrency for the service.
func WithProcessConcurrency(concurrency int64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.processConcurrency = concurrency
	})
}

// WithEndpoints sets the endpoints to communicate with dirk.
func WithEndpoints(endpoints []string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.endpoints = endpoints
	})
}

// WithAccountPaths sets the accounts paths for which to validate.
func WithAccountPaths(accountPaths []string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.accountPaths = accountPaths
	})
}

// WithMajordomo sets the majordomo service for fetching certificate material.
func WithMajordomo(service majordomo.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.majordomo = service
	})
}

// WithClientCertURI sets the URI of the client TLS certificate.
func WithClientCertURI(uri string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientCertURI = uri
	})
}

// WithClientKeyURI sets the URI of the client TLS key.
func WithClientKeyURI(uri string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientKeyURI = uri
	})
}

// WithCACertURI sets the URI of the certificate authority TLS certificate.
func WithCACertURI(uri string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.caCertURI = uri
	})
}

// WithValidatorsManager sets the validators manager.
func WithValidatorsManager(provider validatorsmanager.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatorsManager = provider
	})
}

// WithDomainProvider sets the signature domain provider.
func WithDomainProvider(provider eth2client.DomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.domainProvider = provider
	})
}

// WithFarFutureEpochProvider sets the far future epoch provider.
func WithFarFutureEpochProvider(provider eth2client.FarFutureEpochProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.farFutureEpochProvider = provider
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
		logLevel:      zerolog.GlobalLevel(),
		monitor:       nullmetrics.New(),
		timeout:       30 * time.Second,
		clientMonitor: nullmetrics.New(),
	}
	for _, p := range params {
		if p != nil {
			p.apply(&parameters)
		}
	}

	if err := parameters.validate(); err != nil {
		return nil, err
	}

	return &parameters, nil
}

func (p *parameters) validate() error {
	if p.monitor == nil {
		return errors.New("no monitor specified")
	}
	if p.clientMonitor == nil {
		return errors.New("no client monitor specified")
	}
	if p.timeout == 0 {
		return errors.New("no timeout specified")
	}
	if p.processConcurrency < 1 {
		return errors.New("no process concurrency specified")
	}
	if len(p.endpoints) == 0 {
		return errors.New("no endpoints specified")
	}
	if len(p.accountPaths) == 0 {
		return errors.New("no account paths specified")
	}
	if p.majordomo == nil {
		return errors.New("no majordomo specified")
	}
	if p.clientCertURI == "" {
		return errors.New("no client certificate URI specified")
	}
	if p.clientKeyURI == "" {
		return errors.New("no client key URI specified")
	}
	if p.validatorsManager == nil {
		return errors.New("no validators manager specified")
	}
	if p.domainProvider == nil {
		return errors.New("no domain provider specified")
	}
	if p.farFutureEpochProvider == nil {
		return errors.New("no far future epoch provider specified")
	}
	if p.currentEpochProvider == nil {
		return errors.New("no current epoch provider specified")
	}

	return nil
}
