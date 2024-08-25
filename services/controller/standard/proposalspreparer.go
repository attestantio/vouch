// Copyright © 2020, 2024 Attestant Limited.
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

	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// startProposalsPreparer starts a periodic job to prepare proposal information.
func (s *Service) startProposalsPreparer(ctx context.Context) error {
	runtimeFunc := func(_ context.Context) (time.Time, error) {
		// Schedule for the middle of the slot, three-quarters through the epoch.
		currentEpoch := s.chainTimeService.CurrentEpoch()
		epochDuration := s.chainTimeService.StartOfEpoch(currentEpoch + 1).Sub(s.chainTimeService.StartOfEpoch(currentEpoch))
		currentSlot := s.chainTimeService.CurrentSlot()
		slotDuration := s.chainTimeService.StartOfSlot(currentSlot + 1).Sub(s.chainTimeService.StartOfSlot(currentSlot))
		offset := int(epochDuration.Seconds()*3.0/4.0 + slotDuration.Seconds()/2.0)
		return s.chainTimeService.StartOfEpoch(s.chainTimeService.CurrentEpoch() + 1).Add(time.Duration(offset) * time.Second), nil
	}
	if err := s.scheduler.SchedulePeriodicJob(ctx,
		"Prepare proposals",
		"Prepare proposals ticker",
		runtimeFunc,
		s.prepareProposals,
	); err != nil {
		return errors.Wrap(err, "Failed to schedule proposals preparer")
	}

	return nil
}

// prepareProposals prepares validator information for potential proposals.
func (s *Service) prepareProposals(ctx context.Context) {
	_, span := otel.Tracer("attestantio.vouch.services.controller.standard").Start(ctx, "prepareProposals", trace.WithAttributes(
		attribute.Int64("epoch", util.EpochToInt64(s.chainTimeService.CurrentEpoch())),
	))
	defer span.End()

	started := time.Now()

	if s.chainTimeService.CurrentEpoch() < s.bellatrixForkEpoch {
		s.log.Trace().Dur("elapsed", time.Since(started)).Msg("Not at bellatrix fork epoch; not preparing proposals")
		return
	}

	if err := s.proposalsPreparer.UpdatePreparations(ctx); err != nil {
		s.log.Error().Err(err).Msg("Failed to prepare proposals")
		return
	}

	s.log.Trace().Dur("elapsed", time.Since(started)).Msg("Prepared proposals")
}
