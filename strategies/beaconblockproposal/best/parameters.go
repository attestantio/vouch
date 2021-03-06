// Copyright © 2020 Attestant Limited.
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

// Package best is a strategy that obtains beacon block proposals from multiple
// nodes and selects the best one based on its attestation load.
package best

import (
	"context"
	"runtime"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                     zerolog.Level
	clientMonitor                metrics.ClientMonitor
	processConcurrency           int64
	beaconBlockProposalProviders map[string]eth2client.BeaconBlockProposalProvider
	signedBeaconBlockProvider    eth2client.SignedBeaconBlockProvider
	timeout                      time.Duration
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

// WithTimeout sets the timeout for beacon block proposal requests.
func WithTimeout(timeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.timeout = timeout
	})
}

// WithClientMonitor sets the client monitor for the service.
func WithClientMonitor(monitor metrics.ClientMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientMonitor = monitor
	})
}

// WithProcessConcurrency sets the concurrency for the service.
func WithProcessConcurrency(concurrency int64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.processConcurrency = concurrency
	})
}

// WithBeaconBlockProposalProviders sets the beacon block proposal providers.
func WithBeaconBlockProposalProviders(providers map[string]eth2client.BeaconBlockProposalProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconBlockProposalProviders = providers
	})
}

// WithSignedBeaconBlockProvider sets the signed beacon block provider.
func WithSignedBeaconBlockProvider(provider eth2client.SignedBeaconBlockProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.signedBeaconBlockProvider = provider
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:           zerolog.GlobalLevel(),
		timeout:            2 * time.Second,
		clientMonitor:      nullmetrics.New(context.Background()),
		processConcurrency: int64(runtime.GOMAXPROCS(-1)),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.timeout == 0 {
		return nil, errors.New("no timeout specified")
	}
	if parameters.clientMonitor == nil {
		return nil, errors.New("no client monitor specified")
	}
	if parameters.processConcurrency == 0 {
		return nil, errors.New("no process concurrency specified")
	}
	if len(parameters.beaconBlockProposalProviders) == 0 {
		return nil, errors.New("no beacon block proposal providers specified")
	}
	if parameters.signedBeaconBlockProvider == nil {
		return nil, errors.New("no signed beacon block provider specified")
	}

	return &parameters, nil
}
