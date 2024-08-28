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

// Package best is a strategy that obtains attestation from multiple
// nodes and selects the best one.
package best

import (
	"runtime"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/cache"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                 zerolog.Level
	processConcurrency       int64
	attestationDataProviders map[string]eth2client.AttestationDataProvider
	timeout                  time.Duration
	chainTime                chaintime.Service
	blockRootToSlotCache     cache.BlockRootToSlotProvider
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

// WithProcessConcurrency sets the concurrency for the service.
func WithProcessConcurrency(concurrency int64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.processConcurrency = concurrency
	})
}

// WithAttestationDataProviders sets the beacon block proposal providers.
func WithAttestationDataProviders(providers map[string]eth2client.AttestationDataProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attestationDataProviders = providers
	})
}

// WithTimeout sets the timeout for requests.
func WithTimeout(timeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.timeout = timeout
	})
}

// WithChainTime sets the chain time provider for this service.
func WithChainTime(chainTime chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTime = chainTime
	})
}

// WithBlockRootToSlotCache sets the block root to slot cache.
func WithBlockRootToSlotCache(cache cache.BlockRootToSlotProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.blockRootToSlotCache = cache
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:           zerolog.GlobalLevel(),
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
	if parameters.processConcurrency == 0 {
		return nil, errors.New("no process concurrency specified")
	}
	if len(parameters.attestationDataProviders) == 0 {
		return nil, errors.New("no attestation data providers specified")
	}
	if parameters.chainTime == nil {
		return nil, errors.New("no chain time service specified")
	}
	if parameters.blockRootToSlotCache == nil {
		return nil, errors.New("no block root to slot cache specified")
	}

	return &parameters, nil
}
