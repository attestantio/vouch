// Copyright © 2022 Attestant Limited.
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
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service provides cached information.
type Service struct {
	chainTime       chaintime.Service
	consensusClient eth2client.Service

	blockRootToSlotMu sync.RWMutex
	blockRootToSlot   map[phase0.Root]phase0.Slot
}

// module-wide log.
var log zerolog.Logger

// New creates a new cache.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "cache").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}

	s := &Service{
		chainTime:       parameters.chainTime,
		consensusClient: parameters.consensusClient,
		blockRootToSlot: make(map[phase0.Root]phase0.Slot),
	}

	if eventsProvider, isProvider := s.consensusClient.(eth2client.EventsProvider); isProvider {
		if err := eventsProvider.Events(ctx, []string{"block"}, s.handleBlock); err != nil {
			return nil, errors.Wrap(err, "failed to configure events")
		}
	}

	runtimeFunc := func(ctx context.Context, data interface{}) (time.Time, error) {
		// Run approximately every 15 minutes.
		return time.Now().Add(15 * time.Minute), nil
	}

	if err := parameters.scheduler.SchedulePeriodicJob(ctx,
		"Cache",
		"Clean block root to slot cache",
		runtimeFunc,
		nil,
		s.cleanBlockRootToSlot,
		nil,
	); err != nil {
		log.Error().Err(err).Msg("Failed to schedule periodic clean of block root to slot cache")
	}

	return s, nil
}
