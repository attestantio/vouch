// Copyright © 2020, 2021 Attestant Limited.
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
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/beaconcommitteesubscriber"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/attestantio/vouch/services/synccommitteeaggregator"
	"github.com/attestantio/vouch/services/synccommitteemessenger"
	"github.com/attestantio/vouch/services/synccommitteesubscriber"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is the co-ordination system for vouch.
// It runs purely against clock events, setting up jobs for the validator's processes of block proposal, attestation
// creation and attestation aggregation.
type Service struct {
	monitor                       metrics.ControllerMonitor
	slotDuration                  time.Duration
	slotsPerEpoch                 uint64
	epochsPerSyncCommitteePeriod  uint64
	chainTimeService              chaintime.Service
	proposerDutiesProvider        eth2client.ProposerDutiesProvider
	attesterDutiesProvider        eth2client.AttesterDutiesProvider
	syncCommitteeDutiesProvider   eth2client.SyncCommitteeDutiesProvider
	validatingAccountsProvider    accountmanager.ValidatingAccountsProvider
	scheduler                     scheduler.Service
	attester                      attester.Service
	syncCommitteeMessenger        synccommitteemessenger.Service
	syncCommitteeAggregator       synccommitteeaggregator.Service
	syncCommitteesSubscriber      synccommitteesubscriber.Service
	beaconBlockProposer           beaconblockproposer.Service
	attestationAggregator         attestationaggregator.Service
	beaconCommitteeSubscriber     beaconcommitteesubscriber.Service
	activeValidators              int
	subscriptionInfos             map[phase0.Epoch]map[phase0.Slot]map[phase0.CommitteeIndex]*beaconcommitteesubscriber.Subscription
	subscriptionInfosMutex        sync.Mutex
	accountsRefresher             accountmanager.Refresher
	maxAttestationDelay           time.Duration
	attestationAggregationDelay   time.Duration
	maxSyncCommitteeMessageDelay  time.Duration
	syncCommitteeAggregationDelay time.Duration
	reorgs                        bool

	// Hard fork control
	handlingAltair  bool
	altairForkEpoch phase0.Epoch

	// Tracking for reorgs.
	lastBlockRoot             phase0.Root
	lastBlockEpoch            phase0.Epoch
	currentDutyDependentRoot  phase0.Root
	previousDutyDependentRoot phase0.Root
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

	spec, err := parameters.specProvider.Spec(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain spec")
	}

	tmp, exists := spec["SECONDS_PER_SLOT"]
	if !exists {
		return nil, errors.New("SECONDS_PER_SLOT not found in spec")
	}
	slotDuration, ok := tmp.(time.Duration)
	if !ok {
		return nil, errors.New("SECONDS_PER_SLOT of unexpected type")
	}

	tmp, exists = spec["SLOTS_PER_EPOCH"]
	if !exists {
		return nil, errors.New("SLOTS_PER_EPOCH not found in spec")
	}
	slotsPerEpoch, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("SLOTS_PER_EPOCH of unexpected type")
	}

	var epochsPerSyncCommitteePeriod uint64
	if tmp, exists := spec["EPOCHS_PER_SYNC_COMMITTEE_PERIOD"]; exists {
		tmp2, ok := tmp.(uint64)
		if !ok {
			return nil, errors.New("EPOCHS_PER_SYNC_COMMITTEE_PERIOD of unexpected type")
		}
		epochsPerSyncCommitteePeriod = tmp2
	}

	// Handling altair if we have the service and spec to do so.
	handlingAltair := parameters.syncCommitteeAggregator != nil && epochsPerSyncCommitteePeriod != 0
	if !handlingAltair {
		log.Trace().Msg("Not handling Altair")
	}
	// Fetch the altair fork epoch from the fork schedule.
	var altairForkEpoch phase0.Epoch
	if handlingAltair {
		altairForkEpoch, err = fetchAltairForkEpoch(ctx, parameters.forkScheduleProvider)
		if err != nil {
			// Not handling altair after all.
			handlingAltair = false
		} else {
			log.Trace().Uint64("epoch", uint64(altairForkEpoch)).Msg("Obtained Altair fork epoch")
		}
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
		scheduler:                     parameters.scheduler,
		attester:                      parameters.attester,
		syncCommitteeMessenger:        parameters.syncCommitteeMessenger,
		syncCommitteeAggregator:       parameters.syncCommitteeAggregator,
		beaconBlockProposer:           parameters.beaconBlockProposer,
		attestationAggregator:         parameters.attestationAggregator,
		beaconCommitteeSubscriber:     parameters.beaconCommitteeSubscriber,
		accountsRefresher:             parameters.accountsRefresher,
		maxAttestationDelay:           parameters.maxAttestationDelay,
		attestationAggregationDelay:   parameters.attestationAggregationDelay,
		maxSyncCommitteeMessageDelay:  parameters.maxSyncCommitteeMessageDelay,
		syncCommitteeAggregationDelay: parameters.syncCommitteeAggregationDelay,
		reorgs:                        parameters.reorgs,
		subscriptionInfos:             make(map[phase0.Epoch]map[phase0.Slot]map[phase0.CommitteeIndex]*beaconcommitteesubscriber.Subscription),
		handlingAltair:                handlingAltair,
		altairForkEpoch:               altairForkEpoch,
	}

	// Subscribe to head events.  This allows us to go early for attestations if a block arrives, as well as
	// re-request duties if there is a change in beacon block.
	// This also allows us to re-request duties if the dependent roots change.
	if err := parameters.eventsProvider.Events(ctx, []string{"head"}, s.HandleHeadEvent); err != nil {
		return nil, errors.Wrap(err, "failed to add head event handler")
	}

	if err := s.startTickers(ctx); err != nil {
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
	go s.scheduleProposals(ctx, epoch, validatorIndices, true /* notCurrentSlot */)
	go s.scheduleAttestations(ctx, epoch, validatorIndices, true /* notCurrentSlot */)
	if handlingAltair {
		thisSyncCommitteePeriodStartEpoch := s.firstEpochOfSyncPeriod(uint64(epoch) / s.epochsPerSyncCommitteePeriod)
		go s.scheduleSyncCommitteeMessages(ctx, thisSyncCommitteePeriodStartEpoch, validatorIndices, true /* notCurrentSlot */)
		nextSyncCommitteePeriodStartEpoch := s.firstEpochOfSyncPeriod(uint64(epoch)/s.epochsPerSyncCommitteePeriod + 1)
		go s.scheduleSyncCommitteeMessages(ctx, nextSyncCommitteePeriodStartEpoch, validatorIndices, true /* notCurrentSlot */)
	}
	go s.scheduleAttestations(ctx, epoch+1, nextEpochValidatorIndices, true /* notCurrentSlot */)
	// Update beacon committee subscriptions this and the next epoch.
	go func() {
		subscriptionInfo, err := s.beaconCommitteeSubscriber.Subscribe(ctx, epoch, accounts)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to subscribe to beacon committees")
			return
		}
		s.subscriptionInfosMutex.Lock()
		s.subscriptionInfos[epoch] = subscriptionInfo
		s.subscriptionInfosMutex.Unlock()
	}()
	go func() {
		subscriptionInfo, err := s.beaconCommitteeSubscriber.Subscribe(ctx, epoch+1, nextEpochAccounts)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to subscribe to beacon committees")
			return
		}
		s.subscriptionInfosMutex.Lock()
		s.subscriptionInfos[epoch+1] = subscriptionInfo
		s.subscriptionInfosMutex.Unlock()
	}()

	return s, nil
}

// startTickers starts the various tickers for the controller's operations.
func (s *Service) startTickers(ctx context.Context) error {
	genesisTime := s.chainTimeService.GenesisTime()
	now := time.Now()
	waitedForGenesis := false
	if now.Before(genesisTime) {
		waitedForGenesis = true
		// Wait for genesis.
		log.Info().Str("genesis", fmt.Sprintf("%v", genesisTime)).Msg("Waiting for genesis")
		time.Sleep(time.Until(genesisTime))
	}

	// Start epoch tickers.
	log.Trace().Msg("Starting epoch tickers")
	if err := s.startEpochTicker(ctx, waitedForGenesis); err != nil {
		return errors.Wrap(err, "failed to start epoch ticker")
	}

	// Start account refresher.
	log.Trace().Msg("Starting accounts refresher")
	if err := s.startAccountsRefresher(ctx); err != nil {
		return errors.Wrap(err, "failed to start accounts refresher")
	}

	return nil
}

type epochTickerData struct {
	mutex          sync.Mutex
	latestEpochRan int64
	atGenesis      bool
}

// startEpochTicker starts a ticker that ticks at the beginning of each epoch.
func (s *Service) startEpochTicker(ctx context.Context, waitedForGenesis bool) error {
	runtimeFunc := func(ctx context.Context, data interface{}) (time.Time, error) {
		// Schedule for the beginning of the next epoch.
		return s.chainTimeService.StartOfEpoch(s.chainTimeService.CurrentEpoch() + 1), nil
	}
	data := &epochTickerData{
		latestEpochRan: -1,
		atGenesis:      waitedForGenesis,
	}
	if err := s.scheduler.SchedulePeriodicJob(ctx,
		"Handle new epoch",
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
	waitCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)

	_, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, currentEpoch)
	if err != nil {
		log.Error().Err(err).Uint64("epoch", uint64(currentEpoch)).Msg("Failed to obtain active validators for epoch")
		cancel()
		return
	}

	// Expect at least one validator.
	if len(validatorIndices) == 0 {
		log.Warn().Msg("No active validators; not validating")
		cancel()
		return
	}

	// Done the preparation work available to us; wait for the end of the timer.
	<-waitCtx.Done()
	cancel()

	go s.scheduleProposals(ctx, currentEpoch, validatorIndices, false /* notCurrentSlot */)
	if s.handlingAltair {
		// Handle the Altair hard fork transition epoch.
		if currentEpoch == s.altairForkEpoch {
			log.Trace().Msg("At Altair fork epoch")
			go s.handleAltairForkEpoch(ctx)
		}

		// Update the _next_ period if we are on an EPOCHS_PER_SYNC_COMMITTEE_PERIOD boundary.
		if uint64(currentEpoch)%s.epochsPerSyncCommitteePeriod == 0 {
			go s.scheduleSyncCommitteeMessages(ctx, currentEpoch+phase0.Epoch(s.epochsPerSyncCommitteePeriod), validatorIndices, false /* notCurrentSlot */)
		}
	}

	// Next epoch's attestations and beacon committee subscriptions are now available, but wait until
	// half-way through the epoch to set them up (and half-way through that slot).
	// This allows us to set them up at a time when the beacon node should be less busy.
	if err := s.scheduler.ScheduleJob(ctx,
		"Prepare for epoch",
		fmt.Sprintf("Prepare for epoch %d", currentEpoch+1),
		s.chainTimeService.StartOfSlot(s.chainTimeService.FirstSlotOfEpoch(currentEpoch)+phase0.Slot(s.slotsPerEpoch/2)).Add(s.slotDuration/2),
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
	go func() {
		subscriptionInfo, err := s.beaconCommitteeSubscriber.Subscribe(ctx, prepareForEpochData.epoch, accounts)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to subscribe to beacon committees")
			return
		}
		s.subscriptionInfosMutex.Lock()
		s.subscriptionInfos[prepareForEpochData.epoch] = subscriptionInfo
		s.subscriptionInfosMutex.Unlock()
	}()
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

func fetchAltairForkEpoch(ctx context.Context, forkScheduleProvider eth2client.ForkScheduleProvider) (phase0.Epoch, error) {
	forkSchedule, err := forkScheduleProvider.ForkSchedule(ctx)
	if err != nil {
		return 0, err
	}
	for i := range forkSchedule {
		if bytes.Equal(forkSchedule[i].CurrentVersion[:], forkSchedule[i].PreviousVersion[:]) {
			// This is the genesis fork; ignore it.
			continue
		}
		return forkSchedule[i].Epoch, nil
	}
	return 0, errors.New("no altair fork obtained")
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
		_, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, nextPeriodEpoch)
		if err != nil {
			log.Error().Err(err).Msg("Failed to obtain active validator indices for the period following the Altair fork epoch")
			return
		}
		go s.scheduleSyncCommitteeMessages(ctx, nextPeriodEpoch, validatorIndices, false /* notCurrentSlot */)
	}()
}
