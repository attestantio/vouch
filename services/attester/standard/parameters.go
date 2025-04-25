// Copyright © 2020, 2025 Attestant Limited.
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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                   zerolog.Level
	processConcurrency         int64
	monitor                    metrics.Service
	grace                      time.Duration
	chainTime                  chaintime.Service
	specProvider               eth2client.SpecProvider
	attestationDataProvider    eth2client.AttestationDataProvider
	attestationsSubmitter      submitter.AttestationsSubmitter
	validatingAccountsProvider accountmanager.ValidatingAccountsProvider
	beaconAttestationsSigner   signer.BeaconAttestationsSigner
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

// WithProcessConcurrency sets the concurrency for the service.
func WithProcessConcurrency(concurrency int64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.processConcurrency = concurrency
	})
}

// WithGrace sets the grace before the service starts attesting.
func WithGrace(grace time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.grace = grace
	})
}

// WithChainTime sets the chain time service.
func WithChainTime(service chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTime = service
	})
}

// WithSpecProvider sets the specification provider.
func WithSpecProvider(provider eth2client.SpecProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.specProvider = provider
	})
}

// WithAttestationDataProvider sets the attestation data provider.
func WithAttestationDataProvider(provider eth2client.AttestationDataProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attestationDataProvider = provider
	})
}

// WithAttestationsSubmitter sets the attestations submitter.
func WithAttestationsSubmitter(submitter submitter.AttestationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attestationsSubmitter = submitter
	})
}

// WithMonitor sets the monitor for this module.
func WithMonitor(monitor metrics.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithValidatingAccountsProvider sets the account manager.
func WithValidatingAccountsProvider(provider accountmanager.ValidatingAccountsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatingAccountsProvider = provider
	})
}

// WithBeaconAttestationsSigner sets the beacon attestations signer.
func WithBeaconAttestationsSigner(signer signer.BeaconAttestationsSigner) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconAttestationsSigner = signer
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
	if parameters.chainTime == nil {
		return nil, errors.New("no chain time service specified")
	}
	if parameters.specProvider == nil {
		return nil, errors.New("no spec provider specified")
	}
	if parameters.attestationDataProvider == nil {
		return nil, errors.New("no attestation data provider specified")
	}
	if parameters.attestationsSubmitter == nil {
		return nil, errors.New("no attestations submitter specified")
	}
	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.validatingAccountsProvider == nil {
		return nil, errors.New("no validating accounts provider specified")
	}
	if parameters.beaconAttestationsSigner == nil {
		return nil, errors.New("no beacon attestations signer specified")
	}

	return &parameters, nil
}
