// Copyright © 2020, 2022 Attestant Limited.
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
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                 zerolog.Level
	processConcurrency       int64
	monitor                  metrics.Service
	chainTimeService         chaintime.Service
	attesterDutiesProvider   eth2client.AttesterDutiesProvider
	beaconCommitteeSubmitter submitter.BeaconCommitteeSubscriptionsSubmitter
	attestationAggregator    attestationaggregator.Service
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

// WithMonitor sets the monitor for the module.
func WithMonitor(monitor metrics.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithChainTimeService sets the chaintime service.
func WithChainTimeService(service chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTimeService = service
	})
}

// WithAttesterDutiesProvider sets the attester duties provider.
func WithAttesterDutiesProvider(provider eth2client.AttesterDutiesProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attesterDutiesProvider = provider
	})
}

// WithAttestationAggregator sets the attestation aggregator.
func WithAttestationAggregator(aggregator attestationaggregator.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attestationAggregator = aggregator
	})
}

// WithBeaconCommitteeSubmitter sets the beacon committee subscriptions submitter.
func WithBeaconCommitteeSubmitter(submitter submitter.BeaconCommitteeSubscriptionsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconCommitteeSubmitter = submitter
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

	if parameters.processConcurrency == 0 {
		return nil, errors.New("no process concurrency specified")
	}
	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.chainTimeService == nil {
		return nil, errors.New("no chain time service specified")
	}
	if parameters.attesterDutiesProvider == nil {
		return nil, errors.New("no attester duties provider specified")
	}
	if parameters.attestationAggregator == nil {
		return nil, errors.New("no attestation aggregator specified")
	}
	if parameters.beaconCommitteeSubmitter == nil {
		return nil, errors.New("no beacon committee submitter specified")
	}

	return &parameters, nil
}
