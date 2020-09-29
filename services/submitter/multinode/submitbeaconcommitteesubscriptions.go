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

package multinode

import (
	"context"
	"encoding/json"
	"sync"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"golang.org/x/sync/semaphore"
)

// SubmitBeaconCommitteeSubscriptions submits a batch of beacon committee subscriptions.
func (s *Service) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*submitter.BeaconCommitteeSubscription) error {
	if subscriptions == nil {
		return errors.New("no subscriptions supplied")
	}

	subs := make([]*eth2client.BeaconCommitteeSubscription, len(subscriptions))
	for i, subscription := range subscriptions {
		subs[i] = &eth2client.BeaconCommitteeSubscription{
			Slot:                   subscription.Slot,
			CommitteeIndex:         subscription.CommitteeIndex,
			CommitteeSize:          subscription.CommitteeSize,
			ValidatorIndex:         subscription.ValidatorIndex,
			ValidatorPubKey:        subscription.ValidatorPubKey,
			Aggregate:              subscription.Aggregate,
			SlotSelectionSignature: subscription.Signature,
		}
	}

	sem := semaphore.NewWeighted(s.processConcurrency)
	var wg sync.WaitGroup
	for name, submitter := range s.beaconCommitteeSubscriptionSubmitters {
		wg.Add(1)
		go func(ctx context.Context,
			sem *semaphore.Weighted,
			wg *sync.WaitGroup,
			name string,
			submitter eth2client.BeaconCommitteeSubscriptionsSubmitter,
		) {
			defer wg.Done()
			log := log.With().Str("submitter", name).Int("subscriptions", len(subs)).Logger()
			if err := sem.Acquire(ctx, 1); err != nil {
				log.Error().Err(err).Msg("Failed to acquire semaphore")
				return
			}
			defer sem.Release(1)

			if err := submitter.SubmitBeaconCommitteeSubscriptions(ctx, subs); err != nil {
				log.Warn().Err(err).Msg("Failed to submit beacon committee subscription")
				return
			}
			log.Trace().Msg("Submitted beacon committee subscriptions")
		}(ctx, sem, &wg, name, submitter)
	}
	wg.Wait()

	if e := log.Trace(); e.Enabled() {
		// Summary counts.
		aggregating := 0
		for i := range subscriptions {
			if subscriptions[i].Aggregate {
				aggregating++
			}
		}

		data, err := json.Marshal(subscriptions)
		if err == nil {
			e.Str("subscriptions", string(data)).Int("subscribing", len(subscriptions)).Int("aggregating", aggregating).Msg("Submitted subscriptions")
		}
	}

	return nil
}
