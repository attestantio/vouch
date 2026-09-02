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
	"github.com/attestantio/vouch/services/blockrelay"
	"github.com/attestantio/vouch/services/cache"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/multiinstance"
	"github.com/attestantio/vouch/services/payloadattester"
	"github.com/attestantio/vouch/services/proposalpreparer"
	"github.com/attestantio/vouch/services/proposerpreferences"
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
	executionConfigProvider       blockrelay.ExecutionConfigProvider
	proposerDutiesProvider        eth2client.ProposerDutiesProvider
	attesterDutiesProvider        eth2client.AttesterDutiesProvider
	syncCommitteeDutiesProvider   eth2client.SyncCommitteeDutiesProvider
	ptcDutiesProvider             eth2client.PTCDutiesProvider
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
	payloadAttester               payloadattester.Service
	beaconBlockProposer           beaconblockproposer.Service
	proposerPreferences           proposerpreferences.Publisher
	attestationAggregator         attestationaggregator.Service
	beaconCommitteeSubscriber     beaconcommitteesubscriber.Service
	accountsRefresher             accountmanager.Refresher
	blockToSlotSetter             cache.BlockRootToSlotSetter
	maxProposalDelay              time.Duration
	maxAttestationDelay           time.Duration
	attestationAggregationDelay   time.Duration
	maxSyncCommitteeMessageDelay  time.Duration
	syncCommitteeAggregationDelay time.Duration
	payloadAttestationDelay       time.Duration
	preGloasTimings               dutyTimings
	gloasTimings                  dutyTimings
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

// WithProposerPreferences sets the proposer preferences publisher.
func WithProposerPreferences(preferences proposerpreferences.Publisher) Parameter {
	return parameterFunc(func(p *parameters) {
		p.proposerPreferences = preferences
	})
}

// WithExecutionConfigProvider sets the execution configuration provider.
func WithExecutionConfigProvider(provider blockrelay.ExecutionConfigProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.executionConfigProvider = provider
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
	parameters.setDefaultDelays(spec, slotDuration)
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

// WithPTCDutiesProvider sets the payload timeliness committee duties provider.
func WithPTCDutiesProvider(provider eth2client.PTCDutiesProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.ptcDutiesProvider = provider
	})
}

// WithPayloadAttester sets the payload attester service.
func WithPayloadAttester(attester payloadattester.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.payloadAttester = attester
	})
}

// WithPayloadAttestationDelay sets the delay before submitting payload attestations.
func WithPayloadAttestationDelay(delay time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.payloadAttestationDelay = delay
	})
}

// dutyTimings holds the duty scheduling deadlines, as offsets in to the slot.
type dutyTimings struct {
	maxAttestationDelay           time.Duration
	attestationAggregationDelay   time.Duration
	maxSyncCommitteeMessageDelay  time.Duration
	syncCommitteeAggregationDelay time.Duration
}

// applyOverrides replaces each deadline for which the operator supplied an explicit value.  An
// explicit value is absolute: it applies on both sides of the Gloas fork, as documented for these
// options.
func (t *dutyTimings) applyOverrides(overrides dutyTimings) {
	if overrides.maxAttestationDelay != 0 {
		t.maxAttestationDelay = overrides.maxAttestationDelay
	}
	if overrides.attestationAggregationDelay != 0 {
		t.attestationAggregationDelay = overrides.attestationAggregationDelay
	}
	if overrides.maxSyncCommitteeMessageDelay != 0 {
		t.maxSyncCommitteeMessageDelay = overrides.maxSyncCommitteeMessageDelay
	}
	if overrides.syncCommitteeAggregationDelay != 0 {
		t.syncCommitteeAggregationDelay = overrides.syncCommitteeAggregationDelay
	}
}

// setDefaultDelays derives both the pre-Gloas and the Gloas duty timings.  Both are derived here,
// at construction, but which of them applies is decided per duty from that duty's slot; deciding it
// here would freeze the process on whichever side of the fork it happened to start.
func (p *parameters) setDefaultDelays(spec map[string]any, slotDuration time.Duration) {
	overrides := dutyTimings{
		maxAttestationDelay:           p.maxAttestationDelay,
		attestationAggregationDelay:   p.attestationAggregationDelay,
		maxSyncCommitteeMessageDelay:  p.maxSyncCommitteeMessageDelay,
		syncCommitteeAggregationDelay: p.syncCommitteeAggregationDelay,
	}

	p.preGloasTimings = obtainAttestationTimings(spec, slotDuration, false)
	p.preGloasTimings.applyOverrides(overrides)
	p.gloasTimings = obtainAttestationTimings(spec, slotDuration, true)
	p.gloasTimings.applyOverrides(overrides)

	if p.payloadAttestationDelay == 0 {
		p.payloadAttestationDelay = obtainPayloadAttestationTiming(spec, slotDuration)
	}
}

// gloasSlotDuration provides the slot duration in effect after Gloas.  Gloas serves this in
// milliseconds, and it can differ from SECONDS_PER_SLOT, so every Gloas-derived deadline must be a
// fraction of this value rather than of SECONDS_PER_SLOT.
func gloasSlotDuration(spec map[string]any, slotDuration time.Duration) time.Duration {
	if durationMS, ok := spec["SLOT_DURATION_MS"].(uint64); ok && durationMS != 0 {
		return time.Duration(durationMS) * time.Millisecond
	}

	return slotDuration
}

// dueBPS provides the deadline held in the named spec value, in basis points of the slot duration,
// falling back to the supplied default if the value is not served or is out of range.  The name is
// the exact key.  Gloas redefines the attestation and sync committee deadlines under
// _GLOAS-suffixed keys and keeps serving the unsuffixed keys for the slots before the fork, so
// reading the unsuffixed key after the fork would schedule duties to the deadlines it moved away
// from; the payload attestation deadline is new in Gloas and has no suffixed form.
func dueBPS(spec map[string]any, name string, slotDuration, fallback time.Duration) time.Duration {
	bps, ok := spec[name].(uint64)
	if !ok || bps == 0 || bps > 10000 {
		return fallback
	}

	return slotDuration * time.Duration(bps) / 10000
}

func obtainAttestationTimings(spec map[string]any, slotDuration time.Duration, gloasActive bool) dutyTimings {
	if !gloasActive {
		// The ratios are the pre-Gloas basis-point deadlines: ATTESTATION_DUE_BPS and
		// SYNC_MESSAGE_DUE_BPS are 3333, AGGREGATE_DUE_BPS and CONTRIBUTION_DUE_BPS are 6667.
		return dutyTimings{
			maxAttestationDelay:           slotDuration / 3,     // 4s on a 12-second slot.
			attestationAggregationDelay:   slotDuration * 2 / 3, // 8s on a 12-second slot.
			maxSyncCommitteeMessageDelay:  slotDuration / 3,     // 4s on a 12-second slot.
			syncCommitteeAggregationDelay: slotDuration * 2 / 3, // 8s on a 12-second slot.
		}
	}

	slotDuration = gloasSlotDuration(spec, slotDuration)

	// The fallbacks are the Gloas deadlines themselves: ATTESTATION_DUE_BPS_GLOAS and
	// SYNC_MESSAGE_DUE_BPS_GLOAS are 2500, AGGREGATE_DUE_BPS_GLOAS and CONTRIBUTION_DUE_BPS_GLOAS
	// are 5000.  A node that does not serve them still schedules to this fork's timings.
	return dutyTimings{
		maxAttestationDelay:           dueBPS(spec, "ATTESTATION_DUE_BPS_GLOAS", slotDuration, slotDuration/4),  // 3s on a 12-second slot.
		attestationAggregationDelay:   dueBPS(spec, "AGGREGATE_DUE_BPS_GLOAS", slotDuration, slotDuration/2),    // 6s on a 12-second slot.
		maxSyncCommitteeMessageDelay:  dueBPS(spec, "SYNC_MESSAGE_DUE_BPS_GLOAS", slotDuration, slotDuration/4), // 3s on a 12-second slot.
		syncCommitteeAggregationDelay: dueBPS(spec, "CONTRIBUTION_DUE_BPS_GLOAS", slotDuration, slotDuration/2), // 6s on a 12-second slot.
	}
}

// obtainPayloadAttestationTiming provides the payload attestation deadline.  The duty exists only
// after Gloas, so it always follows the Gloas slot duration.
func obtainPayloadAttestationTiming(spec map[string]any, slotDuration time.Duration) time.Duration {
	slotDuration = gloasSlotDuration(spec, slotDuration)

	return dueBPS(spec, "PAYLOAD_ATTESTATION_DUE_BPS", slotDuration, slotDuration*3/4)
}
