// Copyright © 2020 - 2022 Attestant Limited.
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
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/validatorsmanager"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel               zerolog.Level
	monitor                metrics.AccountManagerMonitor
	timeout                time.Duration
	clientMonitor          metrics.ClientMonitor
	processConcurrency     int64
	endpoints              []string
	accountPaths           []string
	clientCert             []byte
	clientKey              []byte
	caCert                 []byte
	domainProvider         eth2client.DomainProvider
	validatorsManager      validatorsmanager.Service
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
func WithMonitor(monitor metrics.AccountManagerMonitor) Parameter {
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

// WithClientCert sets the bytes of the client TLS certificate.
func WithClientCert(cert []byte) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientCert = cert
	})
}

// WithClientKey sets the bytes of the client TLS key.
func WithClientKey(key []byte) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientKey = key
	})
}

// WithCACert sets the bytes of the certificate authority TLS certificate.
func WithCACert(cert []byte) Parameter {
	return parameterFunc(func(p *parameters) {
		p.caCert = cert
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
		monitor:       nullmetrics.New(context.Background()),
		timeout:       30 * time.Second,
		clientMonitor: nullmetrics.New(context.Background()),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.clientMonitor == nil {
		return nil, errors.New("no client monitor specified")
	}
	if parameters.timeout == 0 {
		return nil, errors.New("no timeout specified")
	}
	if parameters.processConcurrency < 1 {
		return nil, errors.New("no process concurrency specified")
	}
	if len(parameters.endpoints) == 0 {
		return nil, errors.New("no endpoints specified")
	}
	if len(parameters.accountPaths) == 0 {
		return nil, errors.New("no account paths specified")
	}
	if parameters.clientCert == nil {
		return nil, errors.New("no client certificate specified")
	}
	if parameters.clientKey == nil {
		return nil, errors.New("no client key specified")
	}
	if parameters.validatorsManager == nil {
		return nil, errors.New("no validators manager specified")
	}
	if parameters.domainProvider == nil {
		return nil, errors.New("no domain provider specified")
	}
	if parameters.farFutureEpochProvider == nil {
		return nil, errors.New("no far future epoch provider specified")
	}
	if parameters.currentEpochProvider == nil {
		return nil, errors.New("no current epoch provider specified")
	}

	return &parameters, nil
}
