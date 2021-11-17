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
	"time"

	"github.com/pkg/errors"
)

// startAccountsRefresher starts a period job that ticks approximately half-way through an epoch.
func (s *Service) startAccountsRefresher(ctx context.Context) error {
	runtimeFunc := func(ctx context.Context, data interface{}) (time.Time, error) {
		// Schedule for 65 seconds in to the of the next epoch.
		// Doesn't matter too much when we run, but avoid the start of the epoch and
		// also the start of a slot.
		return s.chainTimeService.StartOfEpoch(s.chainTimeService.CurrentEpoch() + 1).Add(65 * time.Second), nil
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
func (s *Service) refreshAccounts(ctx context.Context, data interface{}) {
	started := time.Now()
	s.accountsRefresher.Refresh(ctx)
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Refreshed accounts")
}
