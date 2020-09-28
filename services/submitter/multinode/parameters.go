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

// Package multinode is a strategy that obtains beacon block proposals from multiple
// nodes and selects the best one based on its attestation load.
package multinode

import (
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                               zerolog.Level
	processConcurrency                     int64
	beaconBlockSubmitters                  map[string]eth2client.BeaconBlockSubmitter
	attestationSubmitters                  map[string]eth2client.AttestationSubmitter
	aggregateAttestationsSubmitters        map[string]eth2client.AggregateAttestationsSubmitter
	beaconCommitteeSubscriptionsSubmitters map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter
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

// WithBeaconBlockSubmitters sets the beacon block submitters.
func WithBeaconBlockSubmitters(submitters map[string]eth2client.BeaconBlockSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconBlockSubmitters = submitters
	})
}

// WithAttestationSubmitters sets the attestation submitters.
func WithAttestationSubmitters(submitters map[string]eth2client.AttestationSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attestationSubmitters = submitters
	})
}

// WithAggregateAttestationsSubmitters sets the aggregate attestation submitters.
func WithAggregateAttestationsSubmitters(submitters map[string]eth2client.AggregateAttestationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.aggregateAttestationsSubmitters = submitters
	})
}

// WithBeaconCommitteeSubscriptionsSubmitters sets the attestation submitters.
func WithBeaconCommitteeSubscriptionsSubmitters(submitters map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconCommitteeSubscriptionsSubmitters = submitters
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
	if parameters.beaconBlockSubmitters == nil {
		return nil, errors.New("no beacon block submitters specified")
	}
	if parameters.attestationSubmitters == nil {
		return nil, errors.New("no attestation submitters specified")
	}
	if parameters.aggregateAttestationsSubmitters == nil {
		return nil, errors.New("no aggregate attestations submitters specified")
	}
	if parameters.beaconCommitteeSubscriptionsSubmitters == nil {
		return nil, errors.New("no beacon committee subscription submitters specified")
	}

	return &parameters, nil
}
