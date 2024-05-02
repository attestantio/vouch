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
	"time"

	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
)

// startAccountsRefresher starts a periodic job that refreshes the accounts known by Vouch.
func (s *Service) startAccountsRefresher(ctx context.Context) error {
	runtimeFunc := func(_ context.Context, _ interface{}) (time.Time, error) {
		if s.activeValidators == 0 {
			log.Trace().Msg("No active validators; refreshing accounts next slot")
			return time.Now().Add(s.slotDuration), nil
		}

		// Schedule for the middle of the slot, quarter through the epoch.
		currentEpoch := s.chainTimeService.CurrentEpoch()
		epochDuration := s.chainTimeService.StartOfEpoch(currentEpoch + 1).Sub(s.chainTimeService.StartOfEpoch(currentEpoch))
		currentSlot := s.chainTimeService.CurrentSlot()
		slotDuration := s.chainTimeService.StartOfSlot(currentSlot + 1).Sub(s.chainTimeService.StartOfSlot(currentSlot))
		offset := int(epochDuration.Seconds()/4.0 + slotDuration.Seconds()/2.0)
		return s.chainTimeService.StartOfEpoch(s.chainTimeService.CurrentEpoch() + 1).Add(time.Duration(offset) * time.Second), nil
	}
	if err := s.scheduler.SchedulePeriodicJob(ctx,
		"Refresh accounts",
		"Account refresh ticker",
		runtimeFunc,
		nil,
		s.refreshAccounts,
		nil,
	); err != nil {
		return errors.Wrap(err, "Failed to schedule accounts refresher")
	}

	return nil
}

// refreshAccounts refreshes accounts.
func (s *Service) refreshAccounts(ctx context.Context, _ interface{}) {
	ctx, span := otel.Tracer("attestantio.vouch.services.controller.standard").Start(ctx, "refreshAccounts")
	defer span.End()
	started := time.Now()
	s.accountsRefresher.Refresh(ctx)

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Refreshed accounts")

	// Update active validators count.
	_, validatorIndices, err := s.accountsAndIndicesForEpoch(ctx, s.chainTimeService.CurrentEpoch())
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain active validators on account refresh")
		return
	}
	if len(validatorIndices) != s.activeValidators {
		log.Info().Int("old_validators", s.activeValidators).Int("new_validators", len(validatorIndices)).Msg("Change in number of active validators")
		s.activeValidators = len(validatorIndices)
	}
}
