// Copyright © 2020 - 2026 Attestant Limited.
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
	"github.com/attestantio/vouch/services/multiinstance"
	"github.com/attestantio/vouch/services/proposalpreparer"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/attestantio/vouch/services/synccommitteeaggregator"
	"github.com/attestantio/vouch/services/synccommitteemessenger"
	"github.com/attestantio/vouch/services/synccommitteesubscriber"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	monitor                       metrics.Service
	specProvider                  eth2client.SpecProvider
	chainTimeService              chaintime.Service
	proposerDutiesProvider        eth2client.ProposerDutiesProvider
	attesterDutiesProvider        eth2client.AttesterDutiesProvider
	syncCommitteeDutiesProvider   eth2client.SyncCommitteeDutiesProvider
	validatingAccountsProvider    accountmanager.ValidatingAccountsProvider
	eventsProvider                eth2client.EventsProvider
	beaconBlockHeadersProvider    eth2client.BeaconBlockHeadersProvider
	signedBeaconBlockProvider     eth2client.SignedBeaconBlockProvider
	logLevel                      zerolog.Level
	waitedForGenesis              bool
	syncCommitteesSubscriber      synccommitteesubscriber.Service
	proposalsPreparer             proposalpreparer.Service
	scheduler                     scheduler.Service
	attester                      attester.Service
	syncCommitteeMessenger        synccommitteemessenger.Service
	syncCommitteeAggregator       synccommitteeaggregator.Service
	beaconBlockProposer           beaconblockproposer.Service
	attestationAggregator         attestationaggregator.Service
	beaconCommitteeSubscriber     beaconcommitteesubscriber.Service
	accountsRefresher             accountmanager.Refresher
	blockToSlotSetter             cache.BlockRootToSlotSetter
	maxProposalDelay              time.Duration
	maxAttestationDelay           time.Duration
	attestationAggregationDelay   time.Duration
	maxSyncCommitteeMessageDelay  time.Duration
	syncCommitteeAggregationDelay time.Duration
	verifySyncCommitteeInclusion  bool
	fastTrackAttestations         bool
	fastTrackSyncCommittees       bool
	fastTrackGrace                time.Duration
	multiInstance                 multiinstance.Service
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

// WithVerifySyncCommitteeInclusion sets the flag for whether we should verify sync committee inclusion in SyncAggregate.
func WithVerifySyncCommitteeInclusion(shouldVerify bool) Parameter {
	return parameterFunc(func(p *parameters) {
		p.verifySyncCommitteeInclusion = shouldVerify
	})
}

// WithFastTrackAttestations sets the fast track flag, attesting as soon as possible.
func WithFastTrackAttestations(fastTrack bool) Parameter {
	return parameterFunc(func(p *parameters) {
		p.fastTrackAttestations = fastTrack
	})
}

// WithFastTrackSyncCommittees sets the fast track flag, generating sync committee messages as soon as possible.
func WithFastTrackSyncCommittees(fastTrack bool) Parameter {
	return parameterFunc(func(p *parameters) {
		p.fastTrackSyncCommittees = fastTrack
	})
}

// WithFastTrackGrace sets the grace period before initiating fast track operations.
func WithFastTrackGrace(grace time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.fastTrackGrace = grace
	})
}

// WithMultiInstance sets the multi instance service.
func WithMultiInstance(service multiinstance.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.multiInstance = service
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(ctx context.Context, params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
	}
	for _, p := range params {
		p.apply(&parameters)
	}

	if err := parameters.validate(); err != nil {
		return nil, err
	}
	spec, slotDuration, err := parameters.slotDuration(ctx)
	if err != nil {
		return nil, err
	}
	// maxProposalDelay can be 0, so no check for it here.
	gloasActive := parameters.chainTimeService.CurrentEpoch() >= parameters.chainTimeService.HardForkEpoch(ctx, "GLOAS_FORK_EPOCH")
	parameters.setDefaultDelays(spec, slotDuration, gloasActive)
	// Sync committee duties provider/messenger/aggregator/subscriber are optional so no checks here.

	return &parameters, nil
}

func (p *parameters) validate() error {
	checks := []struct {
		valid bool
		err   string
	}{
		{p.monitor != nil, "no monitor specified"},
		{p.specProvider != nil, "no spec provider specified"},
		{p.chainTimeService != nil, "no chain time service specified"},
		{p.proposerDutiesProvider != nil, "no proposer duties provider specified"},
		{p.attesterDutiesProvider != nil, "no attester duties provider specified"},
		{p.eventsProvider != nil, "no events provider specified"},
		{p.validatingAccountsProvider != nil, "no validating accounts provider specified"},
		{p.proposalsPreparer != nil, "no proposals preparer specified"},
		{p.scheduler != nil, "no scheduler service specified"},
		{p.attester != nil, "no attester specified"},
		{p.beaconBlockProposer != nil, "no beacon block proposer specified"},
		{p.beaconBlockHeadersProvider != nil, "no beacon block headers provider specified"},
		{p.signedBeaconBlockProvider != nil, "no signed beacon block provider specified"},
		{p.attestationAggregator != nil, "no attestation aggregator specified"},
		{p.beaconCommitteeSubscriber != nil, "no beacon committee subscriber specified"},
		{p.accountsRefresher != nil, "no accounts refresher specified"},
		{p.blockToSlotSetter != nil, "no block to slot setter specified"},
		{p.multiInstance != nil, "no multi instance service specified"},
	}
	for _, check := range checks {
		if !check.valid {
			return errors.New(check.err)
		}
	}

	return nil
}

func (p *parameters) slotDuration(ctx context.Context) (map[string]any, time.Duration, error) {
	specResponse, err := p.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to obtain spec")
	}
	secondsPerSlot, exists := specResponse.Data["SECONDS_PER_SLOT"]
	if !exists {
		return nil, 0, errors.New("SECONDS_PER_SLOT not found in spec")
	}
	slotDuration, ok := secondsPerSlot.(time.Duration)
	if !ok {
		return nil, 0, errors.New("SECONDS_PER_SLOT of unexpected type")
	}

	return specResponse.Data, slotDuration, nil
}

func (p *parameters) setDefaultDelays(spec map[string]any, slotDuration time.Duration, gloasActive bool) {
	attestationDue, aggregationDue, syncMessageDue, contributionDue := obtainAttestationTimings(spec, slotDuration, gloasActive)
	if p.maxAttestationDelay == 0 {
		p.maxAttestationDelay = attestationDue
	}
	if p.attestationAggregationDelay == 0 {
		p.attestationAggregationDelay = aggregationDue
	}
	if p.maxSyncCommitteeMessageDelay == 0 {
		p.maxSyncCommitteeMessageDelay = syncMessageDue
	}
	if p.syncCommitteeAggregationDelay == 0 {
		p.syncCommitteeAggregationDelay = contributionDue
	}
}

func obtainAttestationTimings(spec map[string]any, slotDuration time.Duration, gloasActive bool) (time.Duration, time.Duration, time.Duration, time.Duration) {
	attestationDue := slotDuration / 3
	aggregationDue := slotDuration * 2 / 3
	syncMessageDue := slotDuration / 3
	contributionDue := slotDuration * 2 / 3
	if !gloasActive {
		return attestationDue, aggregationDue, syncMessageDue, contributionDue
	}
	if durationMS, ok := spec["SLOT_DURATION_MS"].(uint64); ok {
		slotDuration = time.Duration(durationMS) * time.Millisecond
	}
	dueBPS := func(name string) (uint64, bool) {
		if bps, ok := spec[name+"_GLOAS"].(uint64); ok {
			return bps, true
		}
		bps, ok := spec[name].(uint64)
		return bps, ok
	}
	if bps, ok := dueBPS("ATTESTATION_DUE_BPS"); ok {
		attestationDue = slotDuration * time.Duration(bps) / 10000
	}
	if bps, ok := dueBPS("AGGREGATE_DUE_BPS"); ok {
		aggregationDue = slotDuration * time.Duration(bps) / 10000
	}
	if bps, ok := dueBPS("SYNC_MESSAGE_DUE_BPS"); ok {
		syncMessageDue = slotDuration * time.Duration(bps) / 10000
	}
	if bps, ok := dueBPS("CONTRIBUTION_DUE_BPS"); ok {
		contributionDue = slotDuration * time.Duration(bps) / 10000
	}

	return attestationDue, aggregationDue, syncMessageDue, contributionDue
}
