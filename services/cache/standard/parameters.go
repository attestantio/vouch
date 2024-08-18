// Copyright © 2022, 2024 Attestant Limited.
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
	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                   zerolog.Level
	monitor                    metrics.Service
	chainTime                  chaintime.Service
	signedBeaconBlockProvider  consensusclient.SignedBeaconBlockProvider
	beaconBlockHeadersProvider consensusclient.BeaconBlockHeadersProvider
	eventsProvider             consensusclient.EventsProvider
	scheduler                  scheduler.Service
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(*parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(p *parameters) {
	f(p)
}

// WithLogLevel sets the log level for the service.
func WithLogLevel(logLevel zerolog.Level) Parameter {
	return parameterFunc(func(p *parameters) {
		p.logLevel = logLevel
	})
}

// WithMonitor sets the monitor.
func WithMonitor(monitor metrics.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithSignedBeaconBlockProvider sets the signed beacon block provider for the service.
func WithSignedBeaconBlockProvider(provider consensusclient.SignedBeaconBlockProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.signedBeaconBlockProvider = provider
	})
}

// WithBeaconBlockHeadersProvider sets the beacon block headers provider for the service.
func WithBeaconBlockHeadersProvider(provider consensusclient.BeaconBlockHeadersProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconBlockHeadersProvider = provider
	})
}

// WithEventsProvider sets the events provider for the service.
func WithEventsProvider(provider consensusclient.EventsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.eventsProvider = provider
	})
}

// WithScheduler sets the scheduler for the service..
func WithScheduler(service scheduler.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.scheduler = service
	})
}

// WithChainTime sets the chain time for the service.
func WithChainTime(chainTime chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTime = chainTime
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
		monitor:  nullmetrics.New(),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.chainTime == nil {
		return nil, errors.New("no chain time service specified")
	}
	if parameters.signedBeaconBlockProvider == nil {
		return nil, errors.New("no signed beacon block provider specified")
	}
	if parameters.beaconBlockHeadersProvider == nil {
		return nil, errors.New("no beacon block headers provider specified")
	}
	if parameters.eventsProvider == nil {
		return nil, errors.New("no events provider specified")
	}
	if parameters.scheduler == nil {
		return nil, errors.New("no scheduler specified")
	}

	return &parameters, nil
}
