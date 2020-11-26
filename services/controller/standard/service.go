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
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
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
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
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
	activeValidators           int
	subscriptionInfos          map[spec.Epoch]map[spec.Slot]map[spec.CommitteeIndex]*beaconcommitteesubscriber.Subscription
	subscriptionInfosMutex     sync.Mutex
	accountsRefresher          accountmanager.Refresher
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
		accountsRefresher:          parameters.accountsRefresher,
		subscriptionInfos:          make(map[spec.Epoch]map[spec.Slot]map[spec.CommitteeIndex]*beaconcommitteesubscriber.Subscription),
	}

	// Subscribe to head events.  This allows us to go early for attestations if a block arrives, as well as
	// re-request duties if there is a change in beacon block.
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
	nextEpochAccounts, nextEpochValidatorIndices, err := s.accountsAndIndicesForEpoch(ctx, currentEpoch+1)
	if err != nil {
		log.Error().Err(err).Uint64("epoch", uint64(currentEpoch)).Msg("Failed to obtain active validators for next epoch")
		cancel()
		return
	}

	// Expect at least one validator.
	if len(validatorIndices) == 0 && len(nextEpochValidatorIndices) == 0 {
		log.Warn().Msg("No active validators; not validating")
		cancel()
		return
	}

	// Done the preparation work available to us; wait for the end of the timer.
	<-waitCtx.Done()
	cancel()

	go s.scheduleProposals(ctx, currentEpoch, validatorIndices, false /* notCurrentSlot */)
	go s.scheduleAttestations(ctx, currentEpoch+1, nextEpochValidatorIndices, false /* notCurrentSlot */)
	go func() {
		// Update beacon committee subscriptions for the next epoch.
		subscriptionInfo, err := s.beaconCommitteeSubscriber.Subscribe(ctx, currentEpoch+1, nextEpochAccounts)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to subscribe to beacon committees")
			return
		}
		s.subscriptionInfosMutex.Lock()
		s.subscriptionInfos[currentEpoch+1] = subscriptionInfo
		s.subscriptionInfosMutex.Unlock()
	}()

	epochTickerData.atGenesis = false
}

// accountsAndIndicesForEpoch obtains the accounts and validator indices for the specified epoch.
func (s *Service) accountsAndIndicesForEpoch(ctx context.Context,
	epoch spec.Epoch,
) (
	map[spec.ValidatorIndex]e2wtypes.Account,
	[]spec.ValidatorIndex,
	error,
) {
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpoch(ctx, epoch)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain accounts")
	}

	validatorIndices := make([]spec.ValidatorIndex, 0, len(accounts))
	for index := range accounts {
		validatorIndices = append(validatorIndices, index)
	}

	return accounts, validatorIndices, nil
}
