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
	logLevel                       zerolog.Level
	monitor                        metrics.Service
	specProvider                   eth2client.SpecProvider
	validatingAccountsProvider     accountmanager.ValidatingAccountsProvider
	aggregateAttestationProvider   eth2client.AggregateAttestationProvider
	aggregateAttestationsSubmitter submitter.AggregateAttestationsSubmitter
	slotSelectionSigner            signer.SlotSelectionSigner
	aggregateAndProofSigner        signer.AggregateAndProofSigner
	chainTimeService               chaintime.Service
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

// WithSpecProvider sets the specification provider.
func WithSpecProvider(provider eth2client.SpecProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.specProvider = provider
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

// WithAggregateAttestationProvider sets the aggregate attestation provider.
func WithAggregateAttestationProvider(provider eth2client.AggregateAttestationProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.aggregateAttestationProvider = provider
	})
}

// WithAggregateAttestationsSubmitter sets the aggregate attestation submitter.
func WithAggregateAttestationsSubmitter(submitter submitter.AggregateAttestationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.aggregateAttestationsSubmitter = submitter
	})
}

// WithSlotSelectionSigner sets the slot selection submitter.
func WithSlotSelectionSigner(signer signer.SlotSelectionSigner) Parameter {
	return parameterFunc(func(p *parameters) {
		p.slotSelectionSigner = signer
	})
}

// WithAggregateAndProofSigner sets the aggregate and proof submitter.
func WithAggregateAndProofSigner(signer signer.AggregateAndProofSigner) Parameter {
	return parameterFunc(func(p *parameters) {
		p.aggregateAndProofSigner = signer
	})
}

// WithChainTimeService sets the chain time service.
func WithChainTimeService(service chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTimeService = service
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

	if parameters.specProvider == nil {
		return nil, errors.New("no spec provider specified")
	}
	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.validatingAccountsProvider == nil {
		return nil, errors.New("no validating accounts provider specified")
	}
	if parameters.aggregateAttestationProvider == nil {
		return nil, errors.New("no aggregate attestation provider specified")
	}
	if parameters.aggregateAttestationsSubmitter == nil {
		return nil, errors.New("no aggregate attestations submitter specified")
	}
	if parameters.slotSelectionSigner == nil {
		return nil, errors.New("no slot selection signer specified")
	}
	if parameters.aggregateAndProofSigner == nil {
		return nil, errors.New("no aggregate and proof signer specified")
	}

	return &parameters, nil
}
