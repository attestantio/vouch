// Copyright © 2024 Attestant Limited.
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
	"sync"
	"sync/atomic"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/semaphore"
)

// SubmitBeaconCommitteeSubscriptions submits a batch of beacon committee subscriptions.
func (s *Service) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*api.BeaconCommitteeSubscription) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.submitter.multinode").Start(ctx, "SubmitBeaconCommitteeSubscriptions", trace.WithAttributes(
		attribute.String("strategy", "multinode"),
	))
	defer span.End()

	if subscriptions == nil {
		return errors.New("no subscriptions supplied")
	}

	sem := semaphore.NewWeighted(s.processConcurrency)
	submissionCompleted := &atomic.Bool{}
	w := sync.NewCond(&sync.Mutex{})
	w.L.Lock()
	for name, submitter := range s.beaconCommitteeSubscriptionSubmitters {
		go s.submitBeaconCommitteeSubscriptions(ctx, sem, w, submissionCompleted, name, subscriptions, submitter)
	}
	// Also set a timeout condition, in case no submitters return.
	go func(s *Service, w *sync.Cond) {
		time.Sleep(s.timeout)
		w.Signal()
	}(s, w)
	w.Wait()
	w.L.Unlock()

	var err error
	if !submissionCompleted.Load() {
		err = errors.New("no successful submissions before timeout")
	}

	return err
}

// submitBeaconCommitteeSubscriptions carries out the internal work of submitting beacon committee subscriptions.
// skipcq: RVV-B0001
func (s *Service) submitBeaconCommitteeSubscriptions(ctx context.Context,
	sem *semaphore.Weighted,
	w *sync.Cond,
	submissionCompleted *atomic.Bool,
	name string,
	subscriptions []*api.BeaconCommitteeSubscription,
	submitter eth2client.BeaconCommitteeSubscriptionsSubmitter,
) {
	log := s.log.With().Str("beacon_node_address", name).Int("subscriptions", len(subscriptions)).Logger()
	if err := sem.Acquire(ctx, 1); err != nil {
		log.Error().Err(err).Msg("Failed to acquire semaphore")
		return
	}
	defer sem.Release(1)

	_, address := s.serviceInfo(ctx, submitter)
	started := time.Now()
	err := submitter.SubmitBeaconCommitteeSubscriptions(ctx, subscriptions)

	s.clientMonitor.ClientOperation(address, "submit beacon committee subscription", err == nil, time.Since(started))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to submit beacon committee subscription")
		return
	}

	submissionCompleted.Store(true)
	w.Signal()
	log.Trace().Msg("Submitted beacon committee subscriptions")
}
