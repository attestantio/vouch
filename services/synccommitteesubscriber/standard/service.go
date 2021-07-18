// Copyright © 2021 Attestant Limited.
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

	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is an beacon committee subscriber.
type Service struct {
	monitor   metrics.SyncCommitteeSubscriptionMonitor
	submitter submitter.SyncCommitteeSubscriptionsSubmitter
}

// module-wide log.
var log zerolog.Logger

// New creates a new sync committee subscriber.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "synccommitteesubscriber").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		monitor:   parameters.monitor,
		submitter: parameters.syncCommitteeSubmitter,
	}

	return s, nil
}

// Subscribe subscribes to sync committees given a set of duties.
func (s *Service) Subscribe(ctx context.Context,
	endEpoch phase0.Epoch,
	duties []*api.SyncCommitteeDuty,
) error {
	if len(duties) == 0 {
		// Nothing to do.
		return nil
	}

	started := time.Now()
	log := log.With().Uint64("end_epoch", uint64(endEpoch)).Logger()
	log.Trace().Msg("Subscribing")

	subscriptions := make([]*api.SyncCommitteeSubscription, 0, len(duties))
	for _, duty := range duties {
		subscriptions = append(subscriptions, &api.SyncCommitteeSubscription{
			ValidatorIndex:       duty.ValidatorIndex,
			SyncCommitteeIndices: duty.ValidatorSyncCommitteeIndices,
			UntilEpoch:           endEpoch,
		})
	}

	if err := s.submitter.SubmitSyncCommitteeSubscriptions(ctx, subscriptions); err != nil {
		s.monitor.SyncCommitteeSubscriptionCompleted(started, "failed")
		return errors.Wrap(err, "failed to subscribe to sync committees")
	}

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted subscription request")
	s.monitor.SyncCommitteeSubscriptionCompleted(started, "succeeded")

	return nil
}
