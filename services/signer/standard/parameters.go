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

package standard

import (
	"context"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                            zerolog.Level
	monitor                             metrics.SignerMonitor
	clientMonitor                       metrics.ClientMonitor
	slotsPerEpochProvider               eth2client.SlotsPerEpochProvider
	beaconProposerDomainTypeProvider    eth2client.BeaconProposerDomainProvider
	beaconAttesterDomainTypeProvider    eth2client.BeaconAttesterDomainProvider
	randaoDomainTypeProvider            eth2client.RANDAODomainProvider
	selectionProofDomainTypeProvider    eth2client.SelectionProofDomainProvider
	aggregateAndProofDomainTypeProvider eth2client.AggregateAndProofDomainProvider
	domainProvider                      eth2client.DomainProvider
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
func WithMonitor(monitor metrics.SignerMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithClientMonitor sets the client monitor for the module.
func WithClientMonitor(clientMonitor metrics.ClientMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientMonitor = clientMonitor
	})
}

// WithSlotsPerEpochProvider sets the slots per epoch provider.
func WithSlotsPerEpochProvider(provider eth2client.SlotsPerEpochProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.slotsPerEpochProvider = provider
	})
}

// WithBeaconProposerDomainTypeProvider sets the beacon proposer domain provider.
func WithBeaconProposerDomainTypeProvider(provider eth2client.BeaconProposerDomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconProposerDomainTypeProvider = provider
	})
}

// WithBeaconAttesterDomainTypeProvider sets the beacon attester domain provider.
func WithBeaconAttesterDomainTypeProvider(provider eth2client.BeaconAttesterDomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconAttesterDomainTypeProvider = provider
	})
}

// WithRANDAODomainTypeProvider sets the RANDAO domain provider.
func WithRANDAODomainTypeProvider(provider eth2client.RANDAODomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.randaoDomainTypeProvider = provider
	})
}

// WithSelectionProofDomainTypeProvider sets the RANDAO domain provider.
func WithSelectionProofDomainTypeProvider(provider eth2client.SelectionProofDomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.selectionProofDomainTypeProvider = provider
	})
}

// WithAggregateAndProofDomainTypeProvider sets the aggregate and proof domain provider.
func WithAggregateAndProofDomainTypeProvider(provider eth2client.AggregateAndProofDomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.aggregateAndProofDomainTypeProvider = provider
	})
}

// WithDomainProvider sets the signature domain provider.
func WithDomainProvider(provider eth2client.DomainProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.domainProvider = provider
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:      zerolog.GlobalLevel(),
		monitor:       nullmetrics.New(context.Background()),
		clientMonitor: nullmetrics.New(context.Background()),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.clientMonitor == nil {
		return nil, errors.New("no client monitor specified")
	}
	if parameters.slotsPerEpochProvider == nil {
		return nil, errors.New("no slots per epoch provider specified")
	}
	if parameters.beaconProposerDomainTypeProvider == nil {
		return nil, errors.New("no beacon proposer domain type provider specified")
	}
	if parameters.beaconAttesterDomainTypeProvider == nil {
		return nil, errors.New("no beacon attester domain type provider specified")
	}
	if parameters.randaoDomainTypeProvider == nil {
		return nil, errors.New("no RANDAO domain type provider specified")
	}
	if parameters.selectionProofDomainTypeProvider == nil {
		return nil, errors.New("no selection proof domain type provider specified")
	}
	if parameters.aggregateAndProofDomainTypeProvider == nil {
		return nil, errors.New("no aggregate and proof domain type provider specified")
	}
	if parameters.domainProvider == nil {
		return nil, errors.New("no domain provider specified")
	}

	return &parameters, nil
}
