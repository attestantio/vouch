// Copyright © 2022, 2024 Attestant Limited.
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

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service provides cached information.
type Service struct {
	log zerolog.Logger

	chainTime                  chaintime.Service
	signedBeaconBlockProvider  consensusclient.SignedBeaconBlockProvider
	beaconBlockHeadersProvider consensusclient.BeaconBlockHeadersProvider

	blockRootToSlotMu sync.RWMutex
	blockRootToSlot   map[phase0.Root]phase0.Slot

	executionChainHeadMu     sync.RWMutex
	executionChainHeadHeight uint64
	executionChainHeadRoot   phase0.Hash32
}

// New creates a new cache.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "cache").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}

	s := &Service{
		log:                        log,
		chainTime:                  parameters.chainTime,
		signedBeaconBlockProvider:  parameters.signedBeaconBlockProvider,
		beaconBlockHeadersProvider: parameters.beaconBlockHeadersProvider,
		blockRootToSlot:            make(map[phase0.Root]phase0.Slot),
	}

	// Fetch the current execution head.
	blockResponse, err := s.signedBeaconBlockProvider.SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{
		Block: "head",
	})
	if err != nil {
		// Could happen for various reasons, including the chain not yet being ready.  Log it, but don't error.
		log.Debug().Err(err).Msg("Failed to obtain head block")
	} else {
		s.updateExecutionHeadFromBlock(blockResponse.Data)
	}

	if err := parameters.eventsProvider.Events(ctx, []string{"block"}, s.handleBlock); err != nil {
		return nil, errors.Wrap(err, "failed to configure block event")
	}

	if err := parameters.eventsProvider.Events(ctx, []string{"head"}, s.handleHead); err != nil {
		return nil, errors.Wrap(err, "failed to configure head event")
	}

	if err := parameters.scheduler.SchedulePeriodicJob(ctx,
		"Cache",
		"Clean block root to slot cache",
		func(_ context.Context, _ interface{}) (time.Time, error) {
			// Run approximately every 15 minutes.
			return time.Now().Add(15 * time.Minute), nil
		},
		nil,
		s.cleanBlockRootToSlot,
		nil,
	); err != nil {
		log.Error().Err(err).Msg("Failed to schedule periodic clean of block root to slot cache")
	}

	return s, nil
}
