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

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service provides chain time services.
type Service struct {
	genesisTime   time.Time
	slotDuration  time.Duration
	slotsPerEpoch uint64
}

// module-wide log.
var log zerolog.Logger

// New creates a new controller.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "chaintime").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	genesisTime, err := parameters.genesisTimeProvider.GenesisTime(ctx)
	if err != nil {
		return nil, errors.Wrap(nil, "failed to obtain genesis time")
	}
	log.Trace().Time("genesis_time", genesisTime).Msg("Obtained genesis time")

	slotDuration, err := parameters.slotDurationProvider.SlotDuration(ctx)
	if err != nil {
		return nil, errors.Wrap(nil, "failed to obtain slot duration")
	}
	log.Trace().Dur("slot_duration", slotDuration).Msg("Obtained slot duration")

	slotsPerEpoch, err := parameters.slotsPerEpochProvider.SlotsPerEpoch(ctx)
	if err != nil {
		return nil, errors.Wrap(nil, "failed to obtain slots per epoch")
	}
	log.Trace().Uint64("slots_per_epoch", slotsPerEpoch).Msg("Obtained slots per epoch")

	s := &Service{
		genesisTime:   genesisTime,
		slotDuration:  slotDuration,
		slotsPerEpoch: slotsPerEpoch,
	}

	return s, nil
}

// GenesisTime provides the time of the chain's genesis.
func (s *Service) GenesisTime() time.Time {
	return s.genesisTime
}

// StartOfSlot provides the time at which a given slot starts.
func (s *Service) StartOfSlot(slot spec.Slot) time.Time {
	return s.genesisTime.Add(time.Duration(slot) * s.slotDuration)
}

// StartOfEpoch provides the time at which a given epoch starts.
func (s *Service) StartOfEpoch(epoch spec.Epoch) time.Time {
	return s.genesisTime.Add(time.Duration(uint64(epoch)*s.slotsPerEpoch) * s.slotDuration)
}

// CurrentSlot provides the current slot.
func (s *Service) CurrentSlot() spec.Slot {
	if s.genesisTime.After(time.Now()) {
		return spec.Slot(0)
	}
	return spec.Slot(uint64(time.Since(s.genesisTime).Seconds()) / uint64(s.slotDuration.Seconds()))
}

// CurrentEpoch provides the current epoch.
func (s *Service) CurrentEpoch() spec.Epoch {
	if s.genesisTime.After(time.Now()) {
		return spec.Epoch(0)
	}
	return spec.Epoch(uint64(time.Since(s.genesisTime).Seconds()) / (uint64(s.slotDuration.Seconds()) * s.slotsPerEpoch))
}

// SlotToEpoch provides the epoch of a given slot.
func (s *Service) SlotToEpoch(slot spec.Slot) spec.Epoch {
	return spec.Epoch(uint64(slot) / s.slotsPerEpoch)
}

// FirstSlotOfEpoch provides the first slot of the given epoch.
func (s *Service) FirstSlotOfEpoch(epoch spec.Epoch) spec.Slot {
	return spec.Slot(uint64(epoch) * s.slotsPerEpoch)
}
