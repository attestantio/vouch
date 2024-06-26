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
	"fmt"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
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
	zerologger "github.com/rs/zerolog/log"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// syncCommitteePreparationEpochs is the number of epochs ahead of the sync committee
// period change at which to prepare the relevant jobs.
var syncCommitteePreparationEpochs = uint64(5)

// Service is the co-ordination system for vouch.
// It runs purely against clock events, setting up jobs for the validator's processes of block proposal, attestation
// creation and attestation aggregation.
type Service struct {
	monitor                       metrics.ControllerMonitor
	slotDuration                  time.Duration
	slotsPerEpoch                 uint64
	epochsPerSyncCommitteePeriod  uint64
	chainTimeService              chaintime.Service
	waitedForGenesis              bool
	proposerDutiesProvider        eth2client.ProposerDutiesProvider
	attesterDutiesProvider        eth2client.AttesterDutiesProvider
	syncCommitteeDutiesProvider   eth2client.SyncCommitteeDutiesProvider
	validatingAccountsProvider    accountmanager.ValidatingAccountsProvider
	proposalsPreparer             proposalpreparer.Service
	scheduler                     scheduler.Service
	attester                      attester.Service
	syncCommitteeMessenger        synccommitteemessenger.Service
	syncCommitteeAggregator       synccommitteeaggregator.Service
	syncCommitteesSubscriber      synccommitteesubscriber.Service
	beaconBlockProposer           beaconblockproposer.Service
	beaconBlockHeadersProvider    eth2client.BeaconBlockHeadersProvider
	signedBeaconBlockProvider     eth2client.SignedBeaconBlockProvider
	attestationAggregator         attestationaggregator.Service
	beaconCommitteeSubscriber     beaconcommitteesubscriber.Service
	activeValidators              int
	subscriptionInfos             map[phase0.Epoch]map[phase0.Slot]map[phase0.CommitteeIndex]*beaconcommitteesubscriber.Subscription
	subscriptionInfosMutex        sync.Mutex
	accountsRefresher             accountmanager.Refresher
	blockToSlotSetter             cache.BlockRootToSlotSetter
	maxProposalDelay              time.Duration
	maxAttestationDelay           time.Duration
	attestationAggregationDelay   time.Duration
	maxSyncCommitteeMessageDelay  time.Duration
	syncCommitteeAggregationDelay time.Duration
	fastTrackAttestations         bool
	fastTrackSyncCommittees       bool
	fastTrackGrace                time.Duration

	// Hard fork control
	handlingAltair     bool
	altairForkEpoch    phase0.Epoch
	handlingBellatrix  bool
	bellatrixForkEpoch phase0.Epoch
	capellaForkEpoch   phase0.Epoch

	// Tracking for reorgs.
	lastBlockRoot             phase0.Root
	lastBlockEpoch            phase0.Epoch
	currentDutyDependentRoot  phase0.Root
	previousDutyDependentRoot phase0.Root

	// Tracking for attestations.
	pendingAttestations      map[phase0.Slot]bool
	pendingAttestationsMutex sync.RWMutex
}

// module-wide log.
var log zerolog.Logger

// New creates a new controller.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "controller").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	slotDuration, slotsPerEpoch, epochsPerSyncCommitteePeriod, err := obtainSpecValues(ctx, parameters.specProvider)
	if err != nil {
		return nil, err
	}

	// Handling altair if we have the service and spec to do so.
	handlingAltair := parameters.syncCommitteeAggregator != nil && epochsPerSyncCommitteePeriod != 0
	// Fetch the altair fork epoch from the fork schedule.
	var altairForkEpoch phase0.Epoch
	if handlingAltair {
		altairForkEpoch, err = fetchAltairForkEpoch(ctx, parameters.specProvider)
		if err != nil {
			// Not handling altair after all.
			handlingAltair = false
		} else {
			log.Trace().Uint64("epoch", uint64(altairForkEpoch)).Msg("Obtained Altair fork epoch")
		}
	}
	if !handlingAltair {
		log.Debug().Msg("Not handling Altair")
	}

	// Handling bellatrix if we can obtain its fork epoch.
	handlingBellatrix := true
	// Fetch the bellatrix fork epoch from the fork schedule.
	var bellatrixForkEpoch phase0.Epoch
	bellatrixForkEpoch, err = fetchBellatrixForkEpoch(ctx, parameters.specProvider)
	if err != nil {
		// Not handling bellatrix after all.
		handlingBellatrix = false
		bellatrixForkEpoch = 0xffffffffffffffff
	} else {
		log.Trace().Uint64("epoch", uint64(bellatrixForkEpoch)).Msg("Obtained Bellatrix fork epoch")
	}
	if !handlingBellatrix {
		log.Debug().Msg("Not handling Bellatrix")
	}

	// Fetch the Capella fork epoch from the fork schedule.
	var capellaForkEpoch phase0.Epoch
	capellaForkEpoch, err = fetchCapellaForkEpoch(ctx, parameters.specProvider)
	if err != nil {
		capellaForkEpoch = 0xffffffffffffffff
	} else {
		log.Trace().Uint64("epoch", uint64(capellaForkEpoch)).Msg("Obtained Capella fork epoch")
	}

	s := &Service{
		monitor:                       parameters.monitor,
		slotDuration:                  slotDuration,
		slotsPerEpoch:                 slotsPerEpoch,
		epochsPerSyncCommitteePeriod:  epochsPerSyncCommitteePeriod,
		chainTimeService:              parameters.chainTimeService,
		proposerDutiesProvider:        parameters.proposerDutiesProvider,
		attesterDutiesProvider:        parameters.attesterDutiesProvider,
		syncCommitteeDutiesProvider:   parameters.syncCommitteeDutiesProvider,
		syncCommitteesSubscriber:      parameters.syncCommitteesSubscriber,
		validatingAccountsProvider:    parameters.validatingAccountsProvider,
		proposalsPreparer:             parameters.proposalsPreparer,
		scheduler:                     parameters.scheduler,
		attester:                      parameters.attester,
		syncCommitteeMessenger:        parameters.syncCommitteeMessenger,
		syncCommitteeAggregator:       parameters.syncCommitteeAggregator,
		beaconBlockProposer:           parameters.beaconBlockProposer,
		beaconBlockHeadersProvider:    parameters.beaconBlockHeadersProvider,
		signedBeaconBlockProvider:     parameters.signedBeaconBlockProvider,
		attestationAggregator:         parameters.attestationAggregator,
		beaconCommitteeSubscriber:     parameters.beaconCommitteeSubscriber,
		accountsRefresher:             parameters.accountsRefresher,
		blockToSlotSetter:             parameters.blockToSlotSetter,
		maxProposalDelay:              parameters.maxProposalDelay,
		maxAttestationDelay:           parameters.maxAttestationDelay,
		attestationAggregationDelay:   parameters.attestationAggregationDelay,
		maxSyncCommitteeMessageDelay:  parameters.maxSyncCommitteeMessageDelay,
		syncCommitteeAggregationDelay: parameters.syncCommitteeAggregationDelay,
		fastTrackAttestations:         parameters.fastTrackAttestations,
		fastTrackSyncCommittees:       parameters.fastTrackSyncCommittees,
		fastTrackGrace:                parameters.fastTrackGrace,
		subscriptionInfos:             make(map[phase0.Epoch]map[phase0.Slot]map[phase0.CommitteeIndex]*beaconcommitteesubscriber.Subscription),
		handlingAltair:                handlingAltair,
		altairForkEpoch:               altairForkEpoch,
		handlingBellatrix:             handlingBellatrix,
		bellatrixForkEpoch:            bellatrixForkEpoch,
		capellaForkEpoch:              capellaForkEpoch,
		pendingAttestations:           make(map[phase0.Slot]bool),
	}

	// Subscribe to head events.  This allows us to go early for attestations if a block arrives, as well as
	// re-request duties if there is a change in beacon block.
	// This also allows us to re-request duties if the dependent roots change.
	if err := parameters.eventsProvider.Events(ctx, []string{"head"}, s.HandleHeadEvent); err != nil {
		return nil, errors.Wrap(err, "failed to add head event handler")
	}

	// Subscribe to block events.  This allows us to keep the cache for the block roots to slot number up to date.
	if err := parameters.eventsProvider.Events(ctx, []string{"block"}, s.HandleBlockEvent); err != nil {
		return nil, errors.Wrap(err, "failed to add block event handler")
	}

	// Start tickers, to carry out periodic operations.
	if err := s.startTickers(ctx, handlingBellatrix); err != nil {
		return nil, errors.Wrap(err, "failed to start controller tickers")
	}

	// Run specific actions now so we can carry out duties for the remainder of this epoch.
	epoch := s.chainTimeService.CurrentEpoch()
	accounts, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, epoch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain active validator indices for the current epoch")
	}
	if len(validatorIndices) != s.activeValidators {
		log.Info().Int("old_validators", s.activeValidators).Int("new_validators", len(validatorIndices)).Msg("Change in number of active validators")
		s.activeValidators = len(validatorIndices)
	}
	nextEpochAccounts, nextEpochValidatorIndices, err := s.accountsAndIndicesForEpoch(ctx, epoch+1)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain active validator indices for the next epoch")
	}
	go s.scheduleProposals(ctx, epoch, validatorIndices, !s.waitedForGenesis)
	go s.scheduleAttestations(ctx, epoch, validatorIndices, !s.waitedForGenesis)
	if handlingAltair {
		thisSyncCommitteePeriodStartEpoch := s.firstEpochOfSyncPeriod(uint64(epoch) / s.epochsPerSyncCommitteePeriod)
		go s.scheduleSyncCommitteeMessages(ctx, thisSyncCommitteePeriodStartEpoch, validatorIndices, true /* notCurrentSlot */)
		nextSyncCommitteePeriodStartEpoch := s.firstEpochOfSyncPeriod(uint64(epoch)/s.epochsPerSyncCommitteePeriod + 1)
		if uint64(nextSyncCommitteePeriodStartEpoch-epoch) <= syncCommitteePreparationEpochs {
			go s.scheduleSyncCommitteeMessages(ctx, nextSyncCommitteePeriodStartEpoch, validatorIndices, true /* notCurrentSlot */)
		}
	}
	go s.scheduleAttestations(ctx, epoch+1, nextEpochValidatorIndices, true /* notCurrentSlot */)

	// Update beacon committee subscriptions for this and the next epoch.
	go s.subscribeToBeaconCommittees(ctx, epoch, accounts)
	go s.subscribeToBeaconCommittees(ctx, epoch+1, nextEpochAccounts)

	// Update proposal preparers.
	go func() {
		s.prepareProposals(ctx, nil)
	}()

	return s, nil
}

// startTickers starts the various tickers for the controller's operations.
func (s *Service) startTickers(ctx context.Context,
	handlingBellatrix bool,
) error {
	// Start epoch ticker.
	log.Trace().Msg("Starting epoch tickers")
	if err := s.startEpochTicker(ctx); err != nil {
		return errors.Wrap(err, "failed to start epoch ticker")
	}

	// Start account refresher.
	log.Trace().Msg("Starting accounts refresher")
	if err := s.startAccountsRefresher(ctx); err != nil {
		return errors.Wrap(err, "failed to start accounts refresher")
	}

	// Start proposals preparer.
	if handlingBellatrix {
		log.Trace().Msg("Starting proposals preparer ticker")
		if err := s.startProposalsPreparer(ctx); err != nil {
			return errors.Wrap(err, "failed to start proposals preparer")
		}
	}

	return nil
}

type epochTickerData struct {
	mutex          sync.Mutex
	latestEpochRan int64
	atGenesis      bool
}

// startEpochTicker starts a ticker that ticks at the beginning of each epoch.
func (s *Service) startEpochTicker(ctx context.Context) error {
	runtimeFunc := func(_ context.Context, _ interface{}) (time.Time, error) {
		// Schedule for the beginning of the next epoch.
		return s.chainTimeService.StartOfEpoch(s.chainTimeService.CurrentEpoch() + 1), nil
	}
	data := &epochTickerData{
		latestEpochRan: -1,
		atGenesis:      s.waitedForGenesis,
	}
	if err := s.scheduler.SchedulePeriodicJob(ctx,
		"Epoch",
		"Epoch ticker",
		runtimeFunc,
		data,
		s.epochTicker,
		data,
	); err != nil {
		return errors.Wrap(err, "Failed to schedule epoch ticker")
	}

	return nil
}

// epochTicker sets up the jobs for proposal, attestation and aggregation.
func (s *Service) epochTicker(ctx context.Context, data interface{}) {
	// Ensure we don't run for the same epoch twice.
	epochTickerData := data.(*epochTickerData)
	currentEpoch := s.chainTimeService.CurrentEpoch()
	log.Trace().Uint64("epoch", uint64(currentEpoch)).Msg("Starting per-epoch job")
	epochTickerData.mutex.Lock()
	if epochTickerData.latestEpochRan >= int64(currentEpoch) {
		log.Trace().Uint64("epoch", uint64(currentEpoch)).Msg("Already ran for this epoch; skipping")
		epochTickerData.mutex.Unlock()
		return
	}
	epochTickerData.latestEpochRan = int64(currentEpoch)
	epochTickerData.mutex.Unlock()
	s.monitor.NewEpoch()

	// We wait for the beacon node to update, but keep ourselves busy in the meantime.
	waitCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)

	_, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, currentEpoch)
	if err != nil {
		log.Error().Err(err).Uint64("epoch", uint64(currentEpoch)).Msg("Failed to obtain active validators for epoch")
		cancel()
		return
	}

	// Expect at least one validator, but keep going even if we don't have any
	// as there may be some in the next epoch.
	if len(validatorIndices) == 0 {
		log.Warn().Msg("No active validators; not validating")
	}

	// Done the preparation work available to us; wait for the end of the timer.
	<-waitCtx.Done()
	cancel()

	go s.scheduleProposals(ctx, currentEpoch, validatorIndices, false /* notCurrentSlot */)
	if s.handlingAltair {
		// Handle the Altair hard fork transition epoch.
		if currentEpoch == s.altairForkEpoch {
			log.Info().Msg("At Altair fork epoch")
			go s.handleAltairForkEpoch(ctx)
		}

		// Update the _next_ period if we close to an EPOCHS_PER_SYNC_COMMITTEE_PERIOD boundary.
		if uint64(currentEpoch)%s.epochsPerSyncCommitteePeriod == s.epochsPerSyncCommitteePeriod-syncCommitteePreparationEpochs {
			go s.scheduleSyncCommitteeMessages(ctx, currentEpoch+phase0.Epoch(syncCommitteePreparationEpochs), validatorIndices, false /* notCurrentSlot */)
		}
	}

	if s.handlingBellatrix {
		// Handle the Bellatrix hard fork transition epoch.
		if currentEpoch == s.bellatrixForkEpoch {
			log.Info().Msg("At Bellatrix fork epoch")
			go s.handleBellatrixForkEpoch(ctx)
		}
	}

	// Next epoch's attestations and beacon committee subscriptions are now available, but wait until
	// half-way through the epoch to set them up (and half-way through that slot).
	// This allows us to set them up at a time when the beacon node should be less busy.
	epochDuration := s.chainTimeService.StartOfEpoch(currentEpoch + 1).Sub(s.chainTimeService.StartOfEpoch(currentEpoch))
	currentSlot := s.chainTimeService.CurrentSlot()
	slotDuration := s.chainTimeService.StartOfSlot(currentSlot + 1).Sub(s.chainTimeService.StartOfSlot(currentSlot))
	offset := int(epochDuration.Seconds()/2.0 + slotDuration.Seconds()/2.0)
	if err := s.scheduler.ScheduleJob(ctx,
		"Epoch",
		fmt.Sprintf("Prepare for epoch %d", currentEpoch+1),
		s.chainTimeService.StartOfEpoch(currentEpoch).Add(time.Duration(offset)*time.Second),
		s.prepareForEpoch,
		&prepareForEpochData{
			epoch: currentEpoch + 1,
		},
	); err != nil {
		log.Error().Err(err).Uint64("epoch", uint64(currentEpoch)).Msg("Failed to schedule preparation for following epoch")
		return
	}

	epochTickerData.atGenesis = false
}

type prepareForEpochData struct {
	epoch phase0.Epoch
}

func (s *Service) prepareForEpoch(ctx context.Context, data interface{}) {
	prepareForEpochData := data.(*prepareForEpochData)
	accounts, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, prepareForEpochData.epoch)
	if err != nil {
		log.Error().Err(err).Uint64("epoch", uint64(prepareForEpochData.epoch)).Msg("Failed to obtain active validators for epoch")
		return
	}
	// Expect at least one validator.
	if len(validatorIndices) == 0 {
		log.Warn().Msg("No active validators; not validating")
		return
	}

	go s.scheduleAttestations(ctx, prepareForEpochData.epoch, validatorIndices, false /* notCurrentSlot */)
	go s.subscribeToBeaconCommittees(ctx, prepareForEpochData.epoch, accounts)
}

// accountsAndIndicesForEpoch obtains the accounts and validator indices for the specified epoch.
func (s *Service) accountsAndIndicesForEpoch(ctx context.Context,
	epoch phase0.Epoch,
) (
	map[phase0.ValidatorIndex]e2wtypes.Account,
	[]phase0.ValidatorIndex,
	error,
) {
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpoch(ctx, epoch)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain accounts")
	}

	validatorIndices := make([]phase0.ValidatorIndex, 0, len(accounts))
	for index := range accounts {
		validatorIndices = append(validatorIndices, index)
	}

	return accounts, validatorIndices, nil
}

func fetchAltairForkEpoch(ctx context.Context,
	specProvider eth2client.SpecProvider,
) (
	phase0.Epoch,
	error,
) {
	// Fetch the fork version.
	specResponse, err := specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return 0, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	tmp, exists := spec["ALTAIR_FORK_EPOCH"]
	if !exists {
		return 0, errors.New("altair fork version not known by chain")
	}
	epoch, isEpoch := tmp.(uint64)
	if !isEpoch {
		//nolint:revive
		return 0, errors.New("ALTAIR_FORK_EPOCH is not a uint64!")
	}

	return phase0.Epoch(epoch), nil
}

func fetchBellatrixForkEpoch(ctx context.Context,
	specProvider eth2client.SpecProvider,
) (
	phase0.Epoch,
	error,
) {
	// Fetch the fork version.
	specResponse, err := specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return 0, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	tmp, exists := spec["BELLATRIX_FORK_EPOCH"]
	if !exists {
		return 0, errors.New("bellatrix fork version not known by chain")
	}
	epoch, isEpoch := tmp.(uint64)
	if !isEpoch {
		//nolint:revive
		return 0, errors.New("BELLATRIX_FORK_EPOCH is not a uint64!")
	}

	return phase0.Epoch(epoch), nil
}

func fetchCapellaForkEpoch(ctx context.Context,
	specProvider eth2client.SpecProvider,
) (
	phase0.Epoch,
	error,
) {
	// Fetch the fork version.
	specResponse, err := specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return 0, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	tmp, exists := spec["CAPELLA_FORK_EPOCH"]
	if !exists {
		return 0, errors.New("capella fork version not known by chain")
	}
	epoch, isEpoch := tmp.(uint64)
	if !isEpoch {
		//nolint:revive
		return 0, errors.New("CAPELLA_FORK_EPOCH is not a uint64!")
	}

	return phase0.Epoch(epoch), nil
}

// handleAltairForkEpoch handles changes that need to take place at the Altair hard fork boundary.
func (s *Service) handleAltairForkEpoch(ctx context.Context) {
	if !s.handlingAltair {
		return
	}

	go func() {
		_, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, s.altairForkEpoch)
		if err != nil {
			log.Error().Err(err).Msg("Failed to obtain active validator indices for the Altair fork epoch")
			return
		}
		go s.scheduleSyncCommitteeMessages(ctx, s.altairForkEpoch, validatorIndices, false /* notCurrentSlot */)
	}()

	go func() {
		nextPeriodEpoch := phase0.Epoch((uint64(s.altairForkEpoch)/s.epochsPerSyncCommitteePeriod + 1) * s.epochsPerSyncCommitteePeriod)
		if uint64(nextPeriodEpoch-s.altairForkEpoch) <= syncCommitteePreparationEpochs {
			_, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, nextPeriodEpoch)
			if err != nil {
				log.Error().Err(err).Msg("Failed to obtain active validator indices for the period following the Altair fork epoch")
				return
			}
			go s.scheduleSyncCommitteeMessages(ctx, nextPeriodEpoch, validatorIndices, false /* notCurrentSlot */)
		}
	}()
}

// handleBellatrixForkEpoch handles changes that need to take place at the Bellatrix hard fork boundary.
func (s *Service) handleBellatrixForkEpoch(ctx context.Context) {
	if !s.handlingBellatrix {
		return
	}

	go func() {
		// Send a proposals preparation immediately.
		s.prepareProposals(ctx, nil)
	}()
}

// HasPendingAttestations returns true if there are pending attestations for the given slot.
func (s *Service) HasPendingAttestations(_ context.Context,
	slot phase0.Slot,
) bool {
	s.pendingAttestationsMutex.RLock()
	defer s.pendingAttestationsMutex.RUnlock()

	return s.pendingAttestations[slot]
}

func obtainSpecValues(ctx context.Context,
	specProvider eth2client.SpecProvider,
) (
	time.Duration,
	uint64,
	uint64,
	error,
) {
	specResponse, err := specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return 0, 0, 0, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	tmp, exists := spec["SECONDS_PER_SLOT"]
	if !exists {
		return 0, 0, 0, errors.New("SECONDS_PER_SLOT not found in spec")
	}
	slotDuration, ok := tmp.(time.Duration)
	if !ok {
		return 0, 0, 0, errors.New("SECONDS_PER_SLOT of unexpected type")
	}

	tmp, exists = spec["SLOTS_PER_EPOCH"]
	if !exists {
		return 0, 0, 0, errors.New("SLOTS_PER_EPOCH not found in spec")
	}
	slotsPerEpoch, ok := tmp.(uint64)
	if !ok {
		return 0, 0, 0, errors.New("SLOTS_PER_EPOCH of unexpected type")
	}

	var epochsPerSyncCommitteePeriod uint64
	if tmp, exists := spec["EPOCHS_PER_SYNC_COMMITTEE_PERIOD"]; exists {
		tmp2, ok := tmp.(uint64)
		if !ok {
			return 0, 0, 0, errors.New("EPOCHS_PER_SYNC_COMMITTEE_PERIOD of unexpected type")
		}
		epochsPerSyncCommitteePeriod = tmp2
	}

	return slotDuration, slotsPerEpoch, epochsPerSyncCommitteePeriod, nil
}
