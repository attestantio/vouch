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

package standard

import (
	"bytes"
	"context"
	"sync"
	"time"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the attestation counter.
type Service struct {
	log       zerolog.Logger
	monitor   metrics.Service
	chainTime chaintime.Service

	blocksProvider consensusclient.SignedBeaconBlockProvider
	headVotes      map[phase0.Slot]map[phase0.Root]int
	headVotesMu    sync.Mutex

	bestHeadRoot phase0.Root
}

// New creates a new attestation data counter.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "attestationcounter").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		log:            log,
		monitor:        parameters.monitor,
		chainTime:      parameters.chainTime,
		blocksProvider: parameters.eventsProvider.(consensusclient.SignedBeaconBlockProvider),
		headVotes:      make(map[phase0.Slot]map[phase0.Root]int),
	}

	// Subscribe to attestation events.
	if err := parameters.eventsProvider.Events(ctx, []string{"attestation"}, s.handleAttestation); err != nil {
		return nil, errors.Wrap(err, "failed to add attestation event handler")
	}

	// Subscribe to head events.
	if err := parameters.eventsProvider.Events(ctx, []string{"head"}, s.handleHead); err != nil {
		return nil, errors.Wrap(err, "failed to add head event handler")
	}

	// Start maintenance ticker.
	if err := s.startMaintenanceTicker(ctx, parameters.scheduler); err != nil {
		return nil, errors.Wrap(err, "failed to start maintenance ticker")
	}

	// Start report ticker.
	if err := s.startReportTicker(ctx, parameters.scheduler); err != nil {
		return nil, errors.Wrap(err, "failed to start report ticker")
	}

	return s, nil
}

func (s *Service) reportTicker(_ context.Context, _ any) {
	s.headVotesMu.Lock()

	var bestRoot phase0.Root
	highestVotes := 0
	for root, votes := range s.headVotes[s.chainTime.CurrentSlot()] {
		// s.log.Info().Uint64("slot", uint64(s.chainTime.CurrentSlot())).Stringer("root", root).Int("count", votes).Msg("Possible root")
		if votes > highestVotes {
			bestRoot = root
			highestVotes = votes
		}
	}
	s.headVotesMu.Unlock()

	s.log.Info().Uint64("slot", uint64(s.chainTime.CurrentSlot())).Stringer("root", bestRoot).Int("count", highestVotes).Msg("Best root")
	s.bestHeadRoot = bestRoot
}

func (s *Service) maintenanceTicker(_ context.Context, _ any) {
	// Create a map for roots for this slot.
	s.headVotesMu.Lock()
	s.headVotes[s.chainTime.CurrentSlot()] = make(map[phase0.Root]int)
	s.headVotesMu.Unlock()

	// TODO Remove the map for roots for an old slot.
}

func (s *Service) handleAttestation(event *apiv1.Event) {
	if event.Data == nil {
		return
	}

	attestation := event.Data.(*phase0.Attestation)
	// TODO need to ignore aggregates.
	s.headVotesMu.Lock()
	if _, exists := s.headVotes[attestation.Data.Slot]; !exists {
		// Can be for an old slot.
		s.headVotes[attestation.Data.Slot] = make(map[phase0.Root]int)
	}
	// if _, exists := s.headVotes[attestation.Data.Slot][attestation.Data.BeaconBlockRoot]; !exists {
	// 	s.headVotes[attestation.Data.Slot][attestation.Data.BeaconBlockRoot] = 0
	// }
	s.headVotes[attestation.Data.Slot][attestation.Data.BeaconBlockRoot]++
	s.headVotesMu.Unlock()
}

func (s *Service) handleHead(event *apiv1.Event) {
	if event.Data == nil {
		return
	}

	headEvent := event.Data.(*apiv1.HeadEvent)

	blockResponse, err := s.blocksProvider.SignedBeaconBlock(context.Background(), &api.SignedBeaconBlockOpts{
		Block: headEvent.Block.String(),
	})
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to obtain head block")
		return
	}
	parentRoot, err := blockResponse.Data.ParentRoot()
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to obtain head block parent root")
		return
	}

	if !bytes.Equal(parentRoot[:], s.bestHeadRoot[:]) {
		s.log.Info().Stringer("parent_root", parentRoot).Stringer("expected_root", s.bestHeadRoot).Msg("Head parent root not expected")
	}
	s.log.Info().Uint64("slot", uint64(headEvent.Slot)).Stringer("root", headEvent.Block).Stringer("parent_root", parentRoot).Msg("New head")
}

// startReportTicker starts the ticket reporting on the likely next head 5s into the slot.
func (s *Service) startReportTicker(ctx context.Context, scheduler scheduler.Service) error {
	runtimeFunc := func(_ context.Context, _ any) (time.Time, error) {
		// Schedule for the 5s into the next slot.
		return s.chainTime.StartOfSlot(s.chainTime.CurrentSlot() + 1).Add(5 * time.Second), nil
	}

	if err := scheduler.SchedulePeriodicJob(ctx,
		"Report",
		"Report ticker",
		runtimeFunc,
		nil,
		s.reportTicker,
		nil,
	); err != nil {
		return errors.Wrap(err, "Failed to schedule report ticker")
	}

	return nil
}

func (s *Service) startMaintenanceTicker(ctx context.Context, scheduler scheduler.Service) error {
	runtimeFunc := func(_ context.Context, _ any) (time.Time, error) {
		// Schedule at the start of the next slot.
		return s.chainTime.StartOfSlot(s.chainTime.CurrentSlot() + 1), nil
	}

	if err := scheduler.SchedulePeriodicJob(ctx,
		"Maintenance",
		"Maintenance ticker",
		runtimeFunc,
		nil,
		s.maintenanceTicker,
		nil,
	); err != nil {
		return errors.Wrap(err, "Failed to schedule maintenance ticker")
	}

	return nil
}
