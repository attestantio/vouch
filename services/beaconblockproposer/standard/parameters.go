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
	"errors"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/feerecipientprovider"
	"github.com/attestantio/vouch/services/graffitiprovider"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                   zerolog.Level
	monitor                    metrics.BeaconBlockProposalMonitor
	chainTimeService           chaintime.Service
	proposalProvider           eth2client.BeaconBlockProposalProvider
	validatingAccountsProvider accountmanager.ValidatingAccountsProvider
	feeRecipientProvider       feerecipientprovider.Service
	graffitiProvider           graffitiprovider.Service
	beaconBlockSubmitter       submitter.BeaconBlockSubmitter
	randaoRevealSigner         signer.RANDAORevealSigner
	beaconBlockSigner          signer.BeaconBlockSigner
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

// WithChainTimeService sets the chaintime service.
func WithChainTimeService(service chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTimeService = service
	})
}

// WithProposalDataProvider sets the proposal data provider.
func WithProposalDataProvider(provider eth2client.BeaconBlockProposalProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.proposalProvider = provider
	})
}

// WithMonitor sets the monitor for this module.
func WithMonitor(monitor metrics.BeaconBlockProposalMonitor) Parameter {
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

// WithFeeRecipientProvider sets the fee recipient provider.
func WithFeeRecipientProvider(provider feerecipientprovider.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.feeRecipientProvider = provider
	})
}

// WithGraffitiProvider sets the graffiti provider.
func WithGraffitiProvider(provider graffitiprovider.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.graffitiProvider = provider
	})
}

// WithBeaconBlockSubmitter sets the beacon block submitter.
func WithBeaconBlockSubmitter(submitter submitter.BeaconBlockSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconBlockSubmitter = submitter
	})
}

// WithRANDAORevealSigner sets the RANDAO reveal signer.
func WithRANDAORevealSigner(signer signer.RANDAORevealSigner) Parameter {
	return parameterFunc(func(p *parameters) {
		p.randaoRevealSigner = signer
	})
}

// WithBeaconBlockSigner sets the beacon block signer.
func WithBeaconBlockSigner(signer signer.BeaconBlockSigner) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconBlockSigner = signer
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

	if parameters.proposalProvider == nil {
		return nil, errors.New("no proposal data provider specified")
	}
	if parameters.chainTimeService == nil {
		return nil, errors.New("no chain time service specified")
	}
	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.validatingAccountsProvider == nil {
		return nil, errors.New("no validating accounts provider specified")
	}
	if parameters.feeRecipientProvider == nil {
		return nil, errors.New("no fee recipient provider specified")
	}
	if parameters.beaconBlockSubmitter == nil {
		return nil, errors.New("no beacon block submitter specified")
	}
	if parameters.randaoRevealSigner == nil {
		return nil, errors.New("no RANDAO reveal signer specified")
	}
	if parameters.beaconBlockSigner == nil {
		return nil, errors.New("no beacon block signer specified")
	}

	return &parameters, nil
}
