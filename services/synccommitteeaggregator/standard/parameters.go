// Copyright © 2021 Attestant Limited.
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
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                            zerolog.Level
	monitor                             metrics.SyncCommitteeAggregationMonitor
	specProvider                        eth2client.SpecProvider
	beaconBlockRootProvider             eth2client.BeaconBlockRootProvider
	validatingAccountsProvider          accountmanager.ValidatingAccountsProvider
	aggregateAttestationProvider        eth2client.AggregateAttestationProvider
	prysmAggregateAttestationProvider   eth2client.PrysmAggregateAttestationProvider
	syncCommitteeContributionsSubmitter submitter.SyncCommitteeContributionsSubmitter
	slotSelectionSigner                 signer.SlotSelectionSigner
	contributionAndProofSigner          signer.ContributionAndProofSigner
	syncCommitteeContributionProvider   eth2client.SyncCommitteeContributionProvider
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

// WithSpecProvider sets the spec provider.
func WithSpecProvider(provider eth2client.SpecProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.specProvider = provider
	})
}

// WithBeaconBlockRootProvider sets the beacon block root provider.
func WithBeaconBlockRootProvider(provider eth2client.BeaconBlockRootProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconBlockRootProvider = provider
	})
}

// WithMonitor sets the monitor for this module.
func WithMonitor(monitor metrics.SyncCommitteeAggregationMonitor) Parameter {
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

// WithPrysmAggregateAttestationProvider sets the non-spec aggregate attestation provider.
func WithPrysmAggregateAttestationProvider(provider eth2client.PrysmAggregateAttestationProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.prysmAggregateAttestationProvider = provider
	})
}

// WithSyncCommitteeContributionsSubmitter sets the sync committee contributions submitter.
func WithSyncCommitteeContributionsSubmitter(submitter submitter.SyncCommitteeContributionsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeContributionsSubmitter = submitter
	})
}

// WithSlotSelectionSigner sets the slot selection submitter.
func WithSlotSelectionSigner(signer signer.SlotSelectionSigner) Parameter {
	return parameterFunc(func(p *parameters) {
		p.slotSelectionSigner = signer
	})
}

// WithContributionAndProofSigner sets the contribution and proof submitter.
func WithContributionAndProofSigner(signer signer.ContributionAndProofSigner) Parameter {
	return parameterFunc(func(p *parameters) {
		p.contributionAndProofSigner = signer
	})
}

// WithSyncCommitteeContributionProvider sets the sync committee contribution provider.
func WithSyncCommitteeContributionProvider(provider eth2client.SyncCommitteeContributionProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeContributionProvider = provider
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
	if parameters.beaconBlockRootProvider == nil {
		return nil, errors.New("no beacon block provider specified")
	}
	if parameters.syncCommitteeContributionProvider == nil {
		return nil, errors.New("no sync committee contribution provider specified")
	}
	if parameters.contributionAndProofSigner == nil {
		return nil, errors.New("no contribution and proof signer specified")
	}
	if parameters.syncCommitteeContributionsSubmitter == nil {
		return nil, errors.New("no sync committee contributions submitter specified")
	}
	// 	if parameters.monitor == nil {
	// 		return nil, errors.New("no monitor specified")
	// 	}
	// 	if parameters.validatingAccountsProvider == nil {
	// 		return nil, errors.New("no validating accounts provider specified")
	// 	}
	// 	if parameters.aggregateAttestationProvider == nil && parameters.prysmAggregateAttestationProvider == nil {
	// 		return nil, errors.New("no aggregate attestation provider specified")
	// 	}
	// 	if parameters.syncCommitteeContributionsSubmitter == nil {
	// 		return nil, errors.New("no sync committee contributions submitter specified")
	// 	}
	// 	if parameters.slotSelectionSigner == nil {
	// 		return nil, errors.New("no slot selection signer specified")
	// 	}
	// 	if parameters.contributionAndProofSigner == nil {
	// 		return nil, errors.New("no contribution and proof signer specified")
	// 	}

	return &parameters, nil
}
