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
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/attestantio/vouch/services/synccommitteeaggregator"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                            zerolog.Level
	processConcurrency                  int64
	monitor                             metrics.Service
	chainTimeService                    chaintime.Service
	syncCommitteeAggregator             synccommitteeaggregator.Service
	specProvider                        eth2client.SpecProvider
	beaconBlockRootProvider             eth2client.BeaconBlockRootProvider
	syncCommitteeMessagesSubmitter      submitter.SyncCommitteeMessagesSubmitter
	validatingAccountsProvider          accountmanager.ValidatingAccountsProvider
	syncCommitteeRootSigner             signer.SyncCommitteeRootSigner
	syncCommitteeSelectionSigner        signer.SyncCommitteeSelectionSigner
	syncCommitteeSubscriptionsSubmitter submitter.SyncCommitteeSubscriptionsSubmitter
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

// WithMonitor sets the monitor for this module.
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

// WithSyncCommitteeAggregator sets the sync committee aggregator.
func WithSyncCommitteeAggregator(aggregator synccommitteeaggregator.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeAggregator = aggregator
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

// WithSyncCommitteeMessagesSubmitter sets the sync committee messages submitter.
func WithSyncCommitteeMessagesSubmitter(submitter submitter.SyncCommitteeMessagesSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeMessagesSubmitter = submitter
	})
}

// WithValidatingAccountsProvider sets the account manager.
func WithValidatingAccountsProvider(provider accountmanager.ValidatingAccountsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatingAccountsProvider = provider
	})
}

// WithSyncCommitteeRootSigner sets the sync committee root signer.
func WithSyncCommitteeRootSigner(signer signer.SyncCommitteeRootSigner) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeRootSigner = signer
	})
}

// WithSyncCommitteeSelectionSigner sets the sync committee selection signer.
func WithSyncCommitteeSelectionSigner(signer signer.SyncCommitteeSelectionSigner) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeSelectionSigner = signer
	})
}

// WithSyncCommitteeSubscriptionsSubmitter sets the sync committee subscriptions submitter.
func WithSyncCommitteeSubscriptionsSubmitter(submitter submitter.SyncCommitteeSubscriptionsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeSubscriptionsSubmitter = submitter
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
		monitor:  nullmetrics.New(),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.processConcurrency < 1 {
		return nil, errors.New("no process concurrency specified")
	}
	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.specProvider == nil {
		return nil, errors.New("no spec provider specified")
	}
	if parameters.chainTimeService == nil {
		return nil, errors.New("no chain time service specified")
	}
	if parameters.syncCommitteeAggregator == nil {
		return nil, errors.New("no sync committee aggregator specified")
	}
	if parameters.beaconBlockRootProvider == nil {
		return nil, errors.New("no beacon block root provider specified")
	}
	if parameters.syncCommitteeMessagesSubmitter == nil {
		return nil, errors.New("no sync committee messages submitter specified")
	}
	if parameters.syncCommitteeSubscriptionsSubmitter == nil {
		return nil, errors.New("no sync committee subscriptions submitter specified")
	}
	if parameters.validatingAccountsProvider == nil {
		return nil, errors.New("no validating accounts provider specified")
	}
	if parameters.syncCommitteeSelectionSigner == nil {
		return nil, errors.New("no sync committee selection signer specified")
	}
	if parameters.syncCommitteeRootSigner == nil {
		return nil, errors.New("no sync committee root signer specified")
	}

	return &parameters, nil
}
