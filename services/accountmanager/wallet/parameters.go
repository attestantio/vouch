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

package wallet

import (
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                        zerolog.Level
	monitor                         metrics.AccountManagerMonitor
	locations                       []string
	accountPaths                    []string
	passphrases                     [][]byte
	validatorsProvider              eth2client.ValidatorsProvider
	slotsPerEpochProvider           eth2client.SlotsPerEpochProvider
	beaconProposerDomainProvider    eth2client.BeaconProposerDomainProvider
	beaconAttesterDomainProvider    eth2client.BeaconAttesterDomainProvider
	randaoDomainProvider            eth2client.RANDAODomainProvider
	selectionProofDomainProvider    eth2client.SelectionProofDomainProvider
	aggregateAndProofDomainProvider eth2client.AggregateAndProofDomainProvider
	signatureDomainProvider         eth2client.SignatureDomainProvider
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

// WithLocations sets the locations to look for wallets.
func WithLocations(locations []string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.locations = locations
	})
}

// WithAccountPaths sets the accounts paths for which to validate.
func WithAccountPaths(accountPaths []string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.accountPaths = accountPaths
	})
}

// WithPassphrases sets the passphrases to unlock accounts.
func WithPassphrases(passphrases [][]byte) Parameter {
	return parameterFunc(func(p *parameters) {
		p.passphrases = passphrases
	})
}

// WithValidatorsProvider sets the validator status provider.
func WithValidatorsProvider(provider eth2client.ValidatorsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatorsProvider = provider
	})
}

// WithSlotsPerEpochProvider sets the slots per epoch provider.
func WithSlotsPerEpochProvider(provider eth2client.SlotsPerEpochProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.slotsPerEpochProvider = provider
	})
}

// WithBeaconProposerDomainProvider sets the beacon proposer domain provider.
func WithBeaconProposerDomainProvider(provider eth2client.BeaconProposerDomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconProposerDomainProvider = provider
	})
}

// WithBeaconAttesterDomainProvider sets the beacon attester domain provider.
func WithBeaconAttesterDomainProvider(provider eth2client.BeaconAttesterDomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconAttesterDomainProvider = provider
	})
}

// WithRANDAODomainProvider sets the RANDAO domain provider.
func WithRANDAODomainProvider(provider eth2client.RANDAODomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.randaoDomainProvider = provider
	})
}

// WithSelectionProofDomainProvider sets the RANDAO domain provider.
func WithSelectionProofDomainProvider(provider eth2client.SelectionProofDomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.selectionProofDomainProvider = provider
	})
}

// WithAggregateAndProofDomainProvider sets the aggregate and proof domain provider.
func WithAggregateAndProofDomainProvider(provider eth2client.AggregateAndProofDomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.aggregateAndProofDomainProvider = provider
	})
}

// WithSignatureDomainProvider sets the signature domain provider.
func WithSignatureDomainProvider(provider eth2client.SignatureDomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.signatureDomainProvider = provider
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

	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.accountPaths == nil {
		return nil, errors.New("no account paths specified")
	}
	if len(parameters.passphrases) == 0 {
		return nil, errors.New("no passphrases specified")
	}
	if parameters.validatorsProvider == nil {
		return nil, errors.New("no validators provider specified")
	}
	if parameters.slotsPerEpochProvider == nil {
		return nil, errors.New("no slots per epoch provider specified")
	}
	if parameters.beaconProposerDomainProvider == nil {
		return nil, errors.New("no beacon proposer domain provider specified")
	}
	if parameters.beaconAttesterDomainProvider == nil {
		return nil, errors.New("no beacon attester domain provider specified")
	}
	if parameters.randaoDomainProvider == nil {
		return nil, errors.New("no RANDAO domain provider specified")
	}
	if parameters.selectionProofDomainProvider == nil {
		return nil, errors.New("no selection proof domain provider specified")
	}
	if parameters.aggregateAndProofDomainProvider == nil {
		return nil, errors.New("no aggregate and proof domain provider specified")
	}
	if parameters.signatureDomainProvider == nil {
		return nil, errors.New("no signature domain provider specified")
	}

	return &parameters, nil
}
