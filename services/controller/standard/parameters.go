// Copyright © 2020 - 2024 Attestant Limited.
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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/beaconcommitteesubscriber"
	"github.com/attestantio/vouch/services/cache"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/proposalpreparer"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/attestantio/vouch/services/synccommitteeaggregator"
	"github.com/attestantio/vouch/services/synccommitteemessenger"
	"github.com/attestantio/vouch/services/synccommitteesubscriber"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                      zerolog.Level
	monitor                       metrics.ControllerMonitor
	specProvider                  eth2client.SpecProvider
	chainTimeService              chaintime.Service
	waitedForGenesis              bool
	proposerDutiesProvider        eth2client.ProposerDutiesProvider
	attesterDutiesProvider        eth2client.AttesterDutiesProvider
	syncCommitteeDutiesProvider   eth2client.SyncCommitteeDutiesProvider
	syncCommitteesSubscriber      synccommitteesubscriber.Service
	validatingAccountsProvider    accountmanager.ValidatingAccountsProvider
	proposalsPreparer             proposalpreparer.Service
	scheduler                     scheduler.Service
	eventsProvider                eth2client.EventsProvider
	attester                      attester.Service
	syncCommitteeMessenger        synccommitteemessenger.Service
	syncCommitteeAggregator       synccommitteeaggregator.Service
	beaconBlockProposer           beaconblockproposer.Service
	beaconBlockHeadersProvider    eth2client.BeaconBlockHeadersProvider
	signedBeaconBlockProvider     eth2client.SignedBeaconBlockProvider
	attestationAggregator         attestationaggregator.Service
	beaconCommitteeSubscriber     beaconcommitteesubscriber.Service
	accountsRefresher             accountmanager.Refresher
	blockToSlotSetter             cache.BlockRootToSlotSetter
	maxProposalDelay              time.Duration
	maxAttestationDelay           time.Duration
	attestationAggregationDelay   time.Duration
	maxSyncCommitteeMessageDelay  time.Duration
	syncCommitteeAggregationDelay time.Duration
	fastTrack                     bool
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
func WithMonitor(monitor metrics.ControllerMonitor) Parameter {
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

// WithChainTimeService sets the chain time service.
func WithChainTimeService(service chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTimeService = service
	})
}

// WithWaitedForGenesis is true if we waited for genesis.
func WithWaitedForGenesis(waitedForGenesis bool) Parameter {
	return parameterFunc(func(p *parameters) {
		p.waitedForGenesis = waitedForGenesis
	})
}

// WithProposerDutiesProvider sets the proposer duties provider.
func WithProposerDutiesProvider(provider eth2client.ProposerDutiesProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.proposerDutiesProvider = provider
	})
}

// WithAttesterDutiesProvider sets the attester duties provider.
func WithAttesterDutiesProvider(provider eth2client.AttesterDutiesProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attesterDutiesProvider = provider
	})
}

// WithSyncCommitteeDutiesProvider sets the sync committee duties provider.
func WithSyncCommitteeDutiesProvider(provider eth2client.SyncCommitteeDutiesProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeDutiesProvider = provider
	})
}

// WithSyncCommitteeSubscriber sets the sync committee subscriber.
func WithSyncCommitteeSubscriber(subscriber synccommitteesubscriber.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteesSubscriber = subscriber
	})
}

// WithEventsProvider sets the events provider.
func WithEventsProvider(provider eth2client.EventsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.eventsProvider = provider
	})
}

// WithValidatingAccountsProvider sets the validating accounts provider.
func WithValidatingAccountsProvider(provider accountmanager.ValidatingAccountsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatingAccountsProvider = provider
	})
}

// WithProposalsPreparer sets the proposals preparer.
func WithProposalsPreparer(provider proposalpreparer.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.proposalsPreparer = provider
	})
}

// WithScheduler sets the scheduler.
func WithScheduler(scheduler scheduler.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.scheduler = scheduler
	})
}

// WithAttester sets the attester.
func WithAttester(attester attester.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attester = attester
	})
}

// WithSyncCommitteeMessenger sets the sync committee messenger.
func WithSyncCommitteeMessenger(messenger synccommitteemessenger.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeMessenger = messenger
	})
}

// WithSyncCommitteeAggregator sets the sync committee aggregator.
func WithSyncCommitteeAggregator(aggregator synccommitteeaggregator.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeAggregator = aggregator
	})
}

// WithBeaconBlockHeadersProvider sets the beacon block headers provider.
func WithBeaconBlockHeadersProvider(provider eth2client.BeaconBlockHeadersProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconBlockHeadersProvider = provider
	})
}

// WithSignedBeaconBlockProvider sets the signed beacon block provider.
func WithSignedBeaconBlockProvider(provider eth2client.SignedBeaconBlockProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.signedBeaconBlockProvider = provider
	})
}

// WithBeaconBlockProposer sets the beacon block propser.
func WithBeaconBlockProposer(proposer beaconblockproposer.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconBlockProposer = proposer
	})
}

// WithAttestationAggregator sets the attestation aggregator.
func WithAttestationAggregator(aggregator attestationaggregator.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attestationAggregator = aggregator
	})
}

// WithBeaconCommitteeSubscriber sets the beacon committee subscriber.
func WithBeaconCommitteeSubscriber(subscriber beaconcommitteesubscriber.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconCommitteeSubscriber = subscriber
	})
}

// WithAccountsRefresher sets the account refresher.
func WithAccountsRefresher(refresher accountmanager.Refresher) Parameter {
	return parameterFunc(func(p *parameters) {
		p.accountsRefresher = refresher
	})
}

// WithBlockToSlotSetter sets the setter for the block to slot cache.
func WithBlockToSlotSetter(setter cache.BlockRootToSlotSetter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.blockToSlotSetter = setter
	})
}

// WithMaxProposalDelay sets the maximum delay before proposing.
func WithMaxProposalDelay(delay time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.maxProposalDelay = delay
	})
}

// WithMaxAttestationDelay sets the maximum delay before attesting.
func WithMaxAttestationDelay(delay time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.maxAttestationDelay = delay
	})
}

// WithAttestationAggregationDelay sets the delay before aggregating attestations.
func WithAttestationAggregationDelay(delay time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attestationAggregationDelay = delay
	})
}

// WithMaxSyncCommitteeMessageDelay sets the maximum delay before generating sync committee messages.
func WithMaxSyncCommitteeMessageDelay(delay time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.maxSyncCommitteeMessageDelay = delay
	})
}

// WithSyncCommitteeAggregationDelay sets the delay before aggregating sync committee messages.
func WithSyncCommitteeAggregationDelay(delay time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeAggregationDelay = delay
	})
}

// WithFastTrack sets the fast track flag, attesting as soon as possible.
func WithFastTrack(fastTrack bool) Parameter {
	return parameterFunc(func(p *parameters) {
		p.fastTrack = fastTrack
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
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
	if parameters.chainTimeService == nil {
		return nil, errors.New("no chain time service specified")
	}
	if parameters.proposerDutiesProvider == nil {
		return nil, errors.New("no proposer duties provider specified")
	}
	if parameters.attesterDutiesProvider == nil {
		return nil, errors.New("no attester duties provider specified")
	}
	if parameters.eventsProvider == nil {
		return nil, errors.New("no events provider specified")
	}
	if parameters.validatingAccountsProvider == nil {
		return nil, errors.New("no validating accounts provider specified")
	}
	if parameters.proposalsPreparer == nil {
		return nil, errors.New("no proposals preparer specified")
	}
	if parameters.scheduler == nil {
		return nil, errors.New("no scheduler service specified")
	}
	if parameters.attester == nil {
		return nil, errors.New("no attester specified")
	}
	if parameters.beaconBlockProposer == nil {
		return nil, errors.New("no beacon block proposer specified")
	}
	if parameters.beaconBlockHeadersProvider == nil {
		return nil, errors.New("no beacon block headers provider specified")
	}
	if parameters.signedBeaconBlockProvider == nil {
		return nil, errors.New("no signed beacon block provider specified")
	}
	if parameters.attestationAggregator == nil {
		return nil, errors.New("no attestation aggregator specified")
	}
	if parameters.beaconCommitteeSubscriber == nil {
		return nil, errors.New("no beacon committee subscriber specified")
	}
	if parameters.accountsRefresher == nil {
		return nil, errors.New("no accounts refresher specified")
	}
	if parameters.blockToSlotSetter == nil {
		return nil, errors.New("no block to slot setter specified")
	}
	specResponse, err := parameters.specProvider.Spec(context.Background(), &api.SpecOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data
	tmp, exists := spec["SECONDS_PER_SLOT"]
	if !exists {
		return nil, errors.New("SECONDS_PER_SLOT not found in spec")
	}
	slotDuration, ok := tmp.(time.Duration)
	if !ok {
		return nil, errors.New("SECONDS_PER_SLOT of unexpected type")
	}
	// maxProposalDelay can be 0, so no check for it here.
	if parameters.maxAttestationDelay == 0 {
		parameters.maxAttestationDelay = slotDuration / 3
	}
	if parameters.attestationAggregationDelay == 0 {
		parameters.attestationAggregationDelay = slotDuration * 2 / 3
	}
	if parameters.maxSyncCommitteeMessageDelay == 0 {
		parameters.maxSyncCommitteeMessageDelay = slotDuration / 3
	}
	if parameters.syncCommitteeAggregationDelay == 0 {
		parameters.syncCommitteeAggregationDelay = slotDuration * 2 / 3
	}
	// Sync committee duties provider/messenger/aggregator/subscriber are optional so no checks here.

	return &parameters, nil
}
