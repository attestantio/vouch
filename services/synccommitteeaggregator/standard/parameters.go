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
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                            zerolog.Level
	monitor                             metrics.Service
	specProvider                        eth2client.SpecProvider
	beaconBlockRootProvider             eth2client.BeaconBlockRootProvider
	contributionAndProofSigner          signer.ContributionAndProofSigner
	validatingAccountsProvider          accountmanager.ValidatingAccountsProvider
	syncCommitteeContributionProvider   eth2client.SyncCommitteeContributionProvider
	syncCommitteeContributionsSubmitter submitter.SyncCommitteeContributionsSubmitter
	chainTime                           chaintime.Service
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

// WithMonitor sets the monitor for this module.
func WithMonitor(monitor metrics.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
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

// WithContributionAndProofSigner sets the contribution and proof submitter.
func WithContributionAndProofSigner(signer signer.ContributionAndProofSigner) Parameter {
	return parameterFunc(func(p *parameters) {
		p.contributionAndProofSigner = signer
	})
}

// WithValidatingAccountsProvider sets the account manager.
func WithValidatingAccountsProvider(provider accountmanager.ValidatingAccountsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatingAccountsProvider = provider
	})
}

// WithSyncCommitteeContributionProvider sets the sync committee contribution provider.
func WithSyncCommitteeContributionProvider(provider eth2client.SyncCommitteeContributionProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeContributionProvider = provider
	})
}

// WithSyncCommitteeContributionsSubmitter sets the sync committee contributions submitter.
func WithSyncCommitteeContributionsSubmitter(submitter submitter.SyncCommitteeContributionsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeContributionsSubmitter = submitter
	})
}

// WithChainTime sets the chain time service.
func WithChainTime(service chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTime = service
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
	if parameters.specProvider == nil {
		return nil, errors.New("no spec provider specified")
	}
	if parameters.beaconBlockRootProvider == nil {
		return nil, errors.New("no beacon block root provider specified")
	}
	if parameters.contributionAndProofSigner == nil {
		return nil, errors.New("no contribution and proof signer specified")
	}
	if parameters.validatingAccountsProvider == nil {
		return nil, errors.New("no validating accounts provider specified")
	}
	if parameters.syncCommitteeContributionProvider == nil {
		return nil, errors.New("no sync committee contribution provider specified")
	}
	if parameters.syncCommitteeContributionsSubmitter == nil {
		return nil, errors.New("no sync committee contributions submitter specified")
	}
	if parameters.chainTime == nil {
		return nil, errors.New("no chain time service specified")
	}
	return &parameters, nil
}
