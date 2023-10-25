// Copyright © 2020, 2022 Attestant Limited.
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

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/beaconcommitteesubscriber"
	"github.com/pkg/errors"
	"github.com/sasha-s/go-deadlock"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"golang.org/x/sync/semaphore"
)

// Subscribe subscribes to beacon committees for a given epoch.
// This returns data about the subnets to which we are subscribing.
func (s *Service) Subscribe(ctx context.Context,
	epoch phase0.Epoch,
	accounts map[phase0.ValidatorIndex]e2wtypes.Account,
) (map[phase0.Slot]map[phase0.CommitteeIndex]*beaconcommitteesubscriber.Subscription, error) {
	if len(accounts) == 0 {
		// Nothing to do.
		return map[phase0.Slot]map[phase0.CommitteeIndex]*beaconcommitteesubscriber.Subscription{}, nil
	}

	started := time.Now()
	log := log.With().Uint64("epoch", uint64(epoch)).Logger()
	log.Trace().Msg("Subscribing")

	validatorIndices := make([]phase0.ValidatorIndex, 0, len(accounts))
	for index := range accounts {
		validatorIndices = append(validatorIndices, index)
	}
	attesterDutiesResponse, err := s.attesterDutiesProvider.AttesterDuties(ctx, &api.AttesterDutiesOpts{
		Epoch:   epoch,
		Indices: validatorIndices,
	})
	if err != nil {
		s.monitor.BeaconCommitteeSubscriptionCompleted(started, "failed")
		return nil, errors.Wrap(err, "failed to obtain attester duties")
	}
	attesterDuties := attesterDutiesResponse.Data

	log.Trace().Dur("elapsed", time.Since(started)).Int("accounts", len(validatorIndices)).Msg("Fetched attester duties")
	duties, err := attester.MergeDuties(ctx, attesterDuties)
	if err != nil {
		s.monitor.BeaconCommitteeSubscriptionCompleted(started, "failed")
		return nil, errors.Wrap(err, "failed to merge attester duties")
	}

	subscriptionInfo := s.calculateSubscriptionInfo(ctx, accounts, duties)
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
	go func(currentSlot phase0.Slot) {
		log.Trace().Msg("Submitting subscription")
		subscriptions := make([]*apiv1.BeaconCommitteeSubscription, 0, len(duties))
		for slot, slotInfo := range subscriptionInfo {
			if slot <= currentSlot {
				log.Trace().Uint64("current_slot", uint64(currentSlot)).Uint64("duty_slot", uint64(slot)).Msg("Subscription not for a future slot; ignoring")
				return
			}
			for committeeIndex, info := range slotInfo {
				subscriptions = append(subscriptions, &apiv1.BeaconCommitteeSubscription{
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
	}(s.chainTimeService.CurrentSlot())

	// Return the subscription info so the calling function knows the subnets to which we are subscribing.
	return subscriptionInfo, nil
}

// calculateSubscriptionInfo calculates our beacon block attesation subnet requirements given a set of duties.
// It returns a map of slot => committee => subscription information.
func (s *Service) calculateSubscriptionInfo(ctx context.Context,
	accounts map[phase0.ValidatorIndex]e2wtypes.Account,
	duties []*attester.Duty,
) map[phase0.Slot]map[phase0.CommitteeIndex]*beaconcommitteesubscriber.Subscription {
	// Map is slot => committee => info.
	subscriptionInfo := make(map[phase0.Slot]map[phase0.CommitteeIndex]*beaconcommitteesubscriber.Subscription)
	subscriptionInfoMutex := deadlock.RWMutex{}

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
							duty.Slot(),
							duty.CommitteeSize(duty.CommitteeIndices()[i]))
					if err != nil {
						log.Error().
							Uint64("slot", uint64(duty.Slot())).
							Uint64("validator_index", uint64(duty.ValidatorIndices()[i])).
							Err(err).
							Msg("Failed to calculate if validator is an aggregator")
						return
					}
					// Obtain composite public key if available, otherwise standard public key.
					account := accounts[duty.ValidatorIndices()[i]]
					var pubKey phase0.BLSPubKey
					if provider, isProvider := account.(e2wtypes.AccountCompositePublicKeyProvider); isProvider {
						copy(pubKey[:], provider.CompositePublicKey().Marshal())
					} else {
						copy(pubKey[:], account.PublicKey().Marshal())
					}
					subscriptionInfoMutex.Lock()
					if _, exists := subscriptionInfo[duty.Slot()]; !exists {
						subscriptionInfo[duty.Slot()] = make(map[phase0.CommitteeIndex]*beaconcommitteesubscriber.Subscription)
					}
					subscriptionInfo[duty.Slot()][duty.CommitteeIndices()[i]] = &beaconcommitteesubscriber.Subscription{
						Duty: &apiv1.AttesterDuty{
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

	return subscriptionInfo
}
