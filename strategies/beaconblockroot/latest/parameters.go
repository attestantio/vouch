// Copyright © 2023 Attestant Limited.
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

// Package latest is a strategy that obtains beacon block roots
// from multiple nodes and selects the one relating to the latest slot.
package latest

import (
	"runtime"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/cache"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                 zerolog.Level
	clientMonitor            metrics.ClientMonitor
	processConcurrency       int64
	beaconBlockRootProviders map[string]eth2client.BeaconBlockRootProvider
	timeout                  time.Duration
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

// WithBeaconBlockRootProviders sets the beacon block root providers.
func WithBeaconBlockRootProviders(providers map[string]eth2client.BeaconBlockRootProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconBlockRootProviders = providers
	})
}

// WithTimeout sets the timeout for requests.
func WithTimeout(timeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.timeout = timeout
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
		clientMonitor:      nullmetrics.New(),
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
	if len(parameters.beaconBlockRootProviders) == 0 {
		return nil, errors.New("no beacon block root providers specified")
	}
	if parameters.blockRootToSlotCache == nil {
		return nil, errors.New("no block root to slot cache specified")
	}

	return &parameters, nil
}
