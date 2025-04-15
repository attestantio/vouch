// Copyright © 2024, 2025 Attestant Limited.
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

package staticdelay

import (
	"time"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                   zerolog.Level
	monitor                    metrics.Service
	specProvider               consensusclient.SpecProvider
	attestationPoolProvider    consensusclient.AttestationPoolProvider
	beaconBlockHeadersProvider consensusclient.BeaconBlockHeadersProvider
	chainTime                  chaintime.Service
	attesterDelay              time.Duration
	proposerDelay              time.Duration
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

// WithSpecProvider sets the specification provider for the module.
func WithSpecProvider(provider consensusclient.SpecProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.specProvider = provider
	})
}

// WithAttestationPoolProvider sets the attestation pool provider for the module.
func WithAttestationPoolProvider(provider consensusclient.AttestationPoolProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attestationPoolProvider = provider
	})
}

// WithBeaconBlockHeadersProvider sets the beacon block headers provider for the module.
func WithBeaconBlockHeadersProvider(provider consensusclient.BeaconBlockHeadersProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconBlockHeadersProvider = provider
	})
}

// WithChainTime sets the chaintime provider for the module.
func WithChainTime(provider chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTime = provider
	})
}

// WithAttesterDelay sets the delay for the attester trigger.
func WithAttesterDelay(delay time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attesterDelay = delay
	})
}

// WithProposerDelay sets the delay for the proposer trigger.
func WithProposerDelay(delay time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.proposerDelay = delay
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
		monitor:  nullmetrics.New(),
	}
	for _, p := range params {
		p.apply(&parameters)
	}

	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.specProvider == nil {
		return nil, errors.New("no spec provider specified")
	}
	if parameters.attestationPoolProvider == nil {
		return nil, errors.New("no attestation pool provider specified")
	}
	if parameters.beaconBlockHeadersProvider == nil {
		return nil, errors.New("no beacon block headers provider specified")
	}
	if parameters.chainTime == nil {
		return nil, errors.New("no chain time service specified")
	}
	if parameters.attesterDelay < 0 {
		return nil, errors.New("attester delay cannot be negative")
	}
	if parameters.proposerDelay < 0 {
		return nil, errors.New("proposer delay cannot be negative")
	}

	return &parameters, nil
}
