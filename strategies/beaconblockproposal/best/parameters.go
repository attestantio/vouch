// Copyright © 2020 - 2023 Attestant Limited.
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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/cache"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                  zerolog.Level
	clientMonitor             metrics.ClientMonitor
	processConcurrency        int64
	eventsProvider            eth2client.EventsProvider
	chainTime                 chaintime.Service
	specProvider              eth2client.SpecProvider
	proposalProviders         map[string]eth2client.ProposalProvider
	signedBeaconBlockProvider eth2client.SignedBeaconBlockProvider
	timeout                   time.Duration
	blockRootToSlotCache      cache.BlockRootToSlotProvider
	executionPayloadFactor    float64
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

// WithTimeout sets the timeout for requests.
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

// WithEventsProvider sets the events provider.
func WithEventsProvider(provider eth2client.EventsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.eventsProvider = provider
	})
}

// WithChainTimeService sets the chain time service.
func WithChainTimeService(chainTime chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTime = chainTime
	})
}

// WithSpecProvider sets the beacon spec provider.
func WithSpecProvider(provider eth2client.SpecProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.specProvider = provider
	})
}

// WithProposalProviders sets the proposal providers.
func WithProposalProviders(providers map[string]eth2client.ProposalProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.proposalProviders = providers
	})
}

// WithSignedBeaconBlockProvider sets the signed beacon block provider.
func WithSignedBeaconBlockProvider(provider eth2client.SignedBeaconBlockProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.signedBeaconBlockProvider = provider
	})
}

// WithBlockRootToSlotCache sets the block root to slot cache.
func WithBlockRootToSlotCache(cache cache.BlockRootToSlotProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.blockRootToSlotCache = cache
	})
}

// WithExecutionPayloadFactor sets the relative weight of execution payload gas to block score.
func WithExecutionPayloadFactor(factor float64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.executionPayloadFactor = factor
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:      zerolog.GlobalLevel(),
		clientMonitor: nullmetrics.New(),
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
	if parameters.eventsProvider == nil {
		return nil, errors.New("no events provider specified")
	}
	if parameters.chainTime == nil {
		return nil, errors.New("no chain time service specified")
	}
	if parameters.specProvider == nil {
		return nil, errors.New("no spec provider specified")
	}
	if len(parameters.proposalProviders) == 0 {
		return nil, errors.New("no proposal providers specified")
	}
	if parameters.signedBeaconBlockProvider == nil {
		return nil, errors.New("no signed beacon block provider specified")
	}
	if parameters.blockRootToSlotCache == nil {
		return nil, errors.New("no block root to slot cache specified")
	}

	return &parameters, nil
}
