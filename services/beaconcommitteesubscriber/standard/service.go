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
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/beaconcommitteesubscriber"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/sasha-s/go-deadlock"
	"golang.org/x/sync/semaphore"
)

// Service is an beacon committee subscriber.
type Service struct {
	monitor                metrics.BeaconCommitteeSubscriptionMonitor
	processConcurrency     int64
	attesterDutiesProvider eth2client.AttesterDutiesProvider
	attestationAggregator  attestationaggregator.Service
	submitter              submitter.BeaconCommitteeSubscriptionsSubmitter
}

// module-wide log.
var log zerolog.Logger

// New creates a new beacon committee subscriber.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "beaconcommitteesubscriber").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		processConcurrency:     parameters.processConcurrency,
		monitor:                parameters.monitor,
		attesterDutiesProvider: parameters.attesterDutiesProvider,
		attestationAggregator:  parameters.attestationAggregator,
		submitter:              parameters.beaconCommitteeSubmitter,
	}

	return s, nil
}

// Subscribe subscribes to beacon committees for a given epoch.
// This returns data about the subnets to which we are subscribing.
func (s *Service) Subscribe(ctx context.Context,
	epoch spec.Epoch,
	accounts []accountmanager.ValidatingAccount,
) (map[spec.Slot]map[spec.CommitteeIndex]*beaconcommitteesubscriber.Subscription, error) {
	started := time.Now()

	log := log.With().Uint64("epoch", uint64(epoch)).Logger()
	log.Trace().Msg("Subscribing")

	validatorIDs := make([]spec.ValidatorIndex, len(accounts))
	var err error
	for i, account := range accounts {
		validatorIDs[i], err = account.Index(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain account index")
		}
	}
	attesterDuties, err := s.attesterDutiesProvider.AttesterDuties(ctx, epoch, validatorIDs)
	if err != nil {
		s.monitor.BeaconCommitteeSubscriptionCompleted(started, "failed")
		return nil, errors.Wrap(err, "failed to obtain attester duties")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Int("accounts", len(validatorIDs)).Msg("Fetched attester duties")
	duties, err := attester.MergeDuties(ctx, attesterDuties)
	if err != nil {
		s.monitor.BeaconCommitteeSubscriptionCompleted(started, "failed")
		return nil, errors.Wrap(err, "failed to merge attester duties")
	}

	subscriptionInfo, err := s.calculateSubscriptionInfo(ctx, epoch, accounts, duties)
	if err != nil {
		s.monitor.BeaconCommitteeSubscriptionCompleted(started, "failed")
		return nil, errors.Wrap(err, "failed to calculate subscription duties")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Calculated subscription info")

	// Update metrics.
	subscriptions := 0
	aggregators := 0
	for _, v := range subscriptionInfo {
		for _, v2 := range v {
			subscriptions++
			if v2.IsAggregator {
				aggregators++
			}
		}
	}
	s.monitor.BeaconCommitteeSubscribers(subscriptions)
	s.monitor.BeaconCommitteeAggregators(aggregators)

	// Submit the subscription information.
	go func() {
		log.Trace().Msg("Submitting subscription")
		subscriptions := make([]*api.BeaconCommitteeSubscription, 0, len(duties))
		for slot, slotInfo := range subscriptionInfo {
			for committeeIndex, info := range slotInfo {
				subscriptions = append(subscriptions, &api.BeaconCommitteeSubscription{
					ValidatorIndex:   info.Duty.ValidatorIndex,
					Slot:             slot,
					CommitteeIndex:   committeeIndex,
					CommitteesAtSlot: info.Duty.CommitteesAtSlot,
					IsAggregator:     info.IsAggregator,
				})
			}
		}
		if err := s.submitter.SubmitBeaconCommitteeSubscriptions(ctx, subscriptions); err != nil {
			log.Error().Err(err).Msg("Failed to submit beacon committees")
			s.monitor.BeaconCommitteeSubscriptionCompleted(started, "failed")
			return
		}
		log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted subscription request")
		s.monitor.BeaconCommitteeSubscriptionCompleted(started, "succeeded")
	}()

	// Return the subscription info so the calling function knows the subnets to which we are subscribing.
	return subscriptionInfo, nil
}

// calculateSubscriptionInfo calculates our beacon block attesation subnet requirements given a set of duties.
// It returns a map of slot => committee => subscription information.
func (s *Service) calculateSubscriptionInfo(ctx context.Context,
	epoch spec.Epoch,
	accounts []accountmanager.ValidatingAccount,
	duties []*attester.Duty,
) (map[spec.Slot]map[spec.CommitteeIndex]*beaconcommitteesubscriber.Subscription, error) {

	// Map is slot => committee => info.
	subscriptionInfo := make(map[spec.Slot]map[spec.CommitteeIndex]*beaconcommitteesubscriber.Subscription)
	subscriptionInfoMutex := deadlock.RWMutex{}

	// Map is validator ID => account.
	accountMap := make(map[spec.ValidatorIndex]accountmanager.ValidatingAccount, len(accounts))
	for _, account := range accounts {
		index, err := account.Index(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to obtain account index for account map")
			continue
		}
		accountMap[index] = account
	}

	// Gather aggregators info in parallel.
	// Note that it is possible for two validators to be aggregating for the same (slot,committee index) tuple, however
	// once we have a validator aggregating for a tuple we ignore subsequent validators with the same tuple.
	sem := semaphore.NewWeighted(s.processConcurrency)
	var wg sync.WaitGroup
	for _, duty := range duties {
		wg.Add(1)
		go func(ctx context.Context, sem *semaphore.Weighted, wg *sync.WaitGroup, duty *attester.Duty) {
			defer wg.Done()
			for i := range duty.ValidatorIndices() {
				wg.Add(1)
				go func(ctx context.Context, sem *semaphore.Weighted, wg *sync.WaitGroup, duty *attester.Duty, i int) {
					defer wg.Done()
					if err := sem.Acquire(ctx, 1); err != nil {
						log.Error().Err(err).Msg("Failed to obtain semaphore")
						return
					}
					defer sem.Release(1)
					subscriptionInfoMutex.RLock()
					info, exists := subscriptionInfo[duty.Slot()][duty.CommitteeIndices()[i]]
					subscriptionInfoMutex.RUnlock()
					if exists && info.IsAggregator {
						// Already an aggregator for this slot/committee; don't need to go further.
						return
					}
					isAggregator, signature, err := s.attestationAggregator.(attestationaggregator.IsAggregatorProvider).
						IsAggregator(ctx,
							duty.ValidatorIndices()[i],
							duty.CommitteeIndices()[i],
							duty.Slot(),
							duty.CommitteeSize(duty.CommitteeIndices()[i]))
					if err != nil {
						log.Error().Err(err).Msg("Failed to calculate if validator is an aggregator")
						return
					}
					pubKey, err := accountMap[duty.ValidatorIndices()[i]].PubKey(ctx)
					if err != nil {
						log.Error().Err(err).Msg("Failed to obtain validator's public key")
						return
					}
					subscriptionInfoMutex.Lock()
					if _, exists := subscriptionInfo[duty.Slot()]; !exists {
						subscriptionInfo[duty.Slot()] = make(map[spec.CommitteeIndex]*beaconcommitteesubscriber.Subscription)
					}
					subscriptionInfo[duty.Slot()][duty.CommitteeIndices()[i]] = &beaconcommitteesubscriber.Subscription{
						Duty: &api.AttesterDuty{
							PubKey:                  pubKey,
							Slot:                    duty.Slot(),
							ValidatorIndex:          duty.ValidatorIndices()[i],
							CommitteeIndex:          duty.CommitteeIndices()[i],
							CommitteeLength:         duty.CommitteeSize(duty.CommitteeIndices()[i]),
							CommitteesAtSlot:        duty.CommitteesAtSlot(),
							ValidatorCommitteeIndex: duty.ValidatorCommitteeIndices()[i],
						},
						IsAggregator: isAggregator,
						Signature:    signature,
					}
					subscriptionInfoMutex.Unlock()
				}(ctx, sem, wg, duty, i)
			}
		}(ctx, sem, &wg, duty)
	}
	wg.Wait()

	return subscriptionInfo, nil
}
