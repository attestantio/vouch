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
	"context"
	"fmt"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/beaconcommitteesubscriber"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the co-ordination system for vouch.
// It runs purely against clock events, setting up jobs for the validator's processes of block proposal, attestation
// creation and attestation aggregation.
type Service struct {
	monitor                    metrics.ControllerMonitor
	slotDuration               time.Duration
	slotsPerEpoch              uint64
	chainTimeService           chaintime.Service
	proposerDutiesProvider     eth2client.ProposerDutiesProvider
	attesterDutiesProvider     eth2client.AttesterDutiesProvider
	validatingAccountsProvider accountmanager.ValidatingAccountsProvider
	scheduler                  scheduler.Service
	attester                   attester.Service
	beaconBlockProposer        beaconblockproposer.Service
	attestationAggregator      attestationaggregator.Service
	beaconCommitteeSubscriber  beaconcommitteesubscriber.Service
	activeAccounts             int
	// Epoch => slot => committee => subscription info
	subscriptionInfos      map[uint64]map[uint64]map[uint64]*beaconcommitteesubscriber.Subscription
	subscriptionInfosMutex sync.Mutex
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

	slotDuration, err := parameters.slotDurationProvider.SlotDuration(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain slot duration")
	}

	slotsPerEpoch, err := parameters.slotsPerEpochProvider.SlotsPerEpoch(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain slots per epoch")
	}

	s := &Service{
		monitor:                    parameters.monitor,
		slotDuration:               slotDuration,
		slotsPerEpoch:              slotsPerEpoch,
		chainTimeService:           parameters.chainTimeService,
		proposerDutiesProvider:     parameters.proposerDutiesProvider,
		attesterDutiesProvider:     parameters.attesterDutiesProvider,
		validatingAccountsProvider: parameters.validatingAccountsProvider,
		scheduler:                  parameters.scheduler,
		attester:                   parameters.attester,
		beaconBlockProposer:        parameters.beaconBlockProposer,
		attestationAggregator:      parameters.attestationAggregator,
		beaconCommitteeSubscriber:  parameters.beaconCommitteeSubscriber,
		subscriptionInfos:          make(map[uint64]map[uint64]map[uint64]*beaconcommitteesubscriber.Subscription),
	}

	log.Trace().Msg("Adding beacon chain head updated handler")
	if err := parameters.beaconChainHeadUpdatedSource.AddOnBeaconChainHeadUpdatedHandler(ctx, s); err != nil {
		return nil, errors.Wrap(err, "failed to add beacon chain head updated handler")
	}

	// Subscriptions are usually updated one epoch in advance, but as we're
	// just starting we don't have subscriptions (or subscription information)
	// for this or the next epoch; fetch them now.
	go func() {
		log.Trace().Msg("Fetching initial validator accounts")
		accounts, err := s.validatingAccountsProvider.Accounts(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to obtain accounts for initial validators")
			return
		}
		log.Info().Int("accounts", len(accounts)).Msg("Initial validating accounts")
		if len(accounts) == 0 {
			log.Debug().Msg("No active validating accounts")
			return
		}
		currentEpoch := s.chainTimeService.CurrentEpoch()
		subscriptionInfo, err := s.beaconCommitteeSubscriber.Subscribe(ctx, currentEpoch, accounts)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to fetch initial beacon committees for current epoch")
			return
		}
		s.subscriptionInfosMutex.Lock()
		s.subscriptionInfos[currentEpoch] = subscriptionInfo
		s.subscriptionInfosMutex.Unlock()
		subscriptionInfo, err = s.beaconCommitteeSubscriber.Subscribe(ctx, currentEpoch+1, accounts)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to fetch initial beacon committees for next epoch")
			return
		}
		s.subscriptionInfosMutex.Lock()
		s.subscriptionInfos[currentEpoch+1] = subscriptionInfo
		s.subscriptionInfosMutex.Unlock()
	}()

	if err := s.startTickers(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to start controller tickers")
	}

	return s, nil
}

// startTickers starts the various tickers for the controller's operations.
func (s *Service) startTickers(ctx context.Context) error {
	genesisTime := s.chainTimeService.GenesisTime()
	now := time.Now()
	if now.Before(genesisTime) {
		// Wait for genesis.
		log.Info().Str("genesis", fmt.Sprintf("%v", genesisTime)).Msg("Waiting for genesis")
		time.Sleep(time.Until(genesisTime))
		// Give it another half second to let the beacon node be ready.
		time.Sleep(500 * time.Millisecond)
	}

	// Start epoch ticker.
	log.Trace().Msg("Starting epoch ticker")
	if err := s.startEpochTicker(ctx); err != nil {
		return errors.Wrap(err, "failed to start epoch ticker")
	}

	return nil
}

type epochTickerData struct {
	mutex          sync.Mutex
	latestEpochRan int64
}

// startEpochTicker starts a ticker that ticks at the beginning of each epoch.
func (s *Service) startEpochTicker(ctx context.Context) error {
	runtimeFunc := func(ctx context.Context, data interface{}) (time.Time, error) {
		// Schedule for the beginning of the next epoch.
		return s.chainTimeService.StartOfEpoch(s.chainTimeService.CurrentEpoch() + 1), nil
	}
	data := &epochTickerData{
		latestEpochRan: -1,
	}
	if err := s.scheduler.SchedulePeriodicJob(ctx,
		"Epoch ticker",
		runtimeFunc,
		data,
		s.epochTicker,
		data,
	); err != nil {
		return errors.Wrap(err, "Failed to schedule epoch ticker")
	}

	// Kick off the job immediately to fetch any duties for the current epoch.
	if err := s.scheduler.RunJob(ctx, "Epoch ticker"); err != nil {
		return errors.Wrap(err, "Failed to run epoch ticker")
	}

	return nil
}

// epochTicker sets up the jobs for proposal, attestation and aggregation.
func (s *Service) epochTicker(ctx context.Context, data interface{}) {
	// Ensure we don't run for the same epoch twice.
	epochTickerData := data.(*epochTickerData)
	currentEpoch := s.chainTimeService.CurrentEpoch()
	log.Trace().Uint64("epoch", currentEpoch).Msg("Starting per-epoch duties")
	epochTickerData.mutex.Lock()
	firstRun := epochTickerData.latestEpochRan == -1
	if epochTickerData.latestEpochRan >= int64(currentEpoch) {
		log.Trace().Uint64("epoch", currentEpoch).Msg("Already ran for this epoch; skipping")
		epochTickerData.mutex.Unlock()
		return
	}
	epochTickerData.latestEpochRan = int64(currentEpoch)
	epochTickerData.mutex.Unlock()
	s.monitor.NewEpoch()

	// Wait for half a second for the beacon node to update.
	time.Sleep(500 * time.Millisecond)

	log.Trace().Msg("Updating validating accounts")
	err := s.validatingAccountsProvider.(accountmanager.AccountsUpdater).UpdateAccountsState(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to update account state")
		return
	}
	accounts, err := s.validatingAccountsProvider.Accounts(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain accounts")
		return
	}
	if len(accounts) != s.activeAccounts {
		log.Info().Int("old_accounts", s.activeAccounts).Int("accounts", len(accounts)).Msg("Change in number of validating accounts")
		s.activeAccounts = len(accounts)
	}
	if len(accounts) == 0 {
		// Expect at least one account.
		log.Warn().Msg("No active validating accounts; not validating")
		return
	}

	// Create the jobs for our individual functions.
	go s.createProposerJobs(ctx, currentEpoch, accounts, firstRun)
	go s.createAttesterJobs(ctx, currentEpoch, accounts, firstRun)
	go func() {
		// Update beacon committee subscriptions for the next epoch.
		subscriptionInfo, err := s.beaconCommitteeSubscriber.Subscribe(ctx, currentEpoch+1, accounts)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to subscribe to beacom committees")
			return
		}
		s.subscriptionInfosMutex.Lock()
		s.subscriptionInfos[currentEpoch+1] = subscriptionInfo
		s.subscriptionInfosMutex.Unlock()
	}()
}

// OnBeaconChainHeadUpdated runs attestations for a slot immediately, if the update is for the current slot.
func (s *Service) OnBeaconChainHeadUpdated(ctx context.Context, slot uint64, stateRoot []byte, bodyRoot []byte, epochTransitioni bool) {
	if slot != s.chainTimeService.CurrentSlot() {
		return
	}
	s.monitor.BlockDelay(time.Since(s.chainTimeService.StartOfSlot(slot)))

	jobName := fmt.Sprintf("Beacon block attestations for slot %d", slot)
	if s.scheduler.JobExists(ctx, jobName) {
		log.Trace().Uint64("slot", slot).Msg("Kicking off attestations for slot early due to receiving relevant block")
		if err := s.scheduler.RunJobIfExists(ctx, jobName); err != nil {
			log.Error().Str("job", jobName).Err(err).Msg("Failed to run attester job")
		}
	}

	// Remove old subscriptions if present.
	delete(s.subscriptionInfos, s.chainTimeService.SlotToEpoch(slot)-2)
}
