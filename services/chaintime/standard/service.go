// Copyright © 2020 - 2024 Attestant Limited.
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
	"fmt"
	"time"

	client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service provides chain time services.
type Service struct {
	log           zerolog.Logger
	genesisTime   time.Time
	slotDuration  time.Duration
	slotsPerEpoch uint64
	specProvider  client.SpecProvider
}

// New creates a new controller.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "chaintime").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	genesisResponse, err := parameters.genesisProvider.Genesis(ctx, &api.GenesisOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain genesis")
	}
	genesisTime := genesisResponse.Data.GenesisTime
	log.Trace().Time("genesis_time", genesisTime).Msg("Obtained genesis time")

	specResponse, err := parameters.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	tmp, exists := spec["SECONDS_PER_SLOT"]
	if !exists {
		return nil, errors.New("SECONDS_PER_SLOT not found in spec")
	}
	slotDuration, ok := tmp.(time.Duration)
	if !ok {
		return nil, errors.New("SECONDS_PER_SLOT of unexpected type")
	}
	log.Trace().Dur("slot_duration", slotDuration).Msg("Obtained slot duration")

	tmp, exists = spec["SLOTS_PER_EPOCH"]
	if !exists {
		return nil, errors.New("SLOTS_PER_EPOCH not found in spec")
	}
	slotsPerEpoch, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("SLOTS_PER_EPOCH of unexpected type")
	}
	log.Trace().Uint64("slots_per_epoch", slotsPerEpoch).Msg("Obtained slots per epoch")

	s := &Service{
		log:           log,
		genesisTime:   genesisTime,
		slotDuration:  slotDuration,
		slotsPerEpoch: slotsPerEpoch,
		specProvider:  parameters.specProvider,
	}

	return s, nil
}

// GenesisTime provides the time of the chain's genesis.
func (s *Service) GenesisTime() time.Time {
	return s.genesisTime
}

// StartOfSlot provides the time at which a given slot starts.
func (s *Service) StartOfSlot(slot phase0.Slot) time.Time {
	return s.genesisTime.Add(time.Duration(slot) * s.slotDuration)
}

// StartOfEpoch provides the time at which a given epoch starts.
func (s *Service) StartOfEpoch(epoch phase0.Epoch) time.Time {
	return s.genesisTime.Add(time.Duration(uint64(epoch)*s.slotsPerEpoch) * s.slotDuration)
}

// CurrentSlot provides the current slot.
func (s *Service) CurrentSlot() phase0.Slot {
	if s.genesisTime.After(time.Now()) {
		return phase0.Slot(0)
	}
	return phase0.Slot(uint64(time.Since(s.genesisTime).Seconds()) / uint64(s.slotDuration.Seconds()))
}

// CurrentEpoch provides the current epoch.
func (s *Service) CurrentEpoch() phase0.Epoch {
	if s.genesisTime.After(time.Now()) {
		return phase0.Epoch(0)
	}
	return phase0.Epoch(uint64(time.Since(s.genesisTime).Seconds()) / (uint64(s.slotDuration.Seconds()) * s.slotsPerEpoch))
}

// SlotToEpoch provides the epoch of a given slot.
func (s *Service) SlotToEpoch(slot phase0.Slot) phase0.Epoch {
	return phase0.Epoch(uint64(slot) / s.slotsPerEpoch)
}

// FirstSlotOfEpoch provides the first slot of the given epoch.
func (s *Service) FirstSlotOfEpoch(epoch phase0.Epoch) phase0.Slot {
	return phase0.Slot(uint64(epoch) * s.slotsPerEpoch)
}

// HardForkEpoch returns the activation epoch of the specified hard fork or far future epoch if missing.
func (s *Service) HardForkEpoch(ctx context.Context, hardForkName string) phase0.Epoch {
	forkEpoch, err := s.getHardForkEpoch(ctx, hardForkName)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to obtain hard fork")
		return 0xffffffffffffffff
	}
	return forkEpoch
}

func (s *Service) getHardForkEpoch(ctx context.Context, hardForkName string) (phase0.Epoch, error) {
	// Fetch the fork version.
	specResponse, err := s.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return 0, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	tmp, exists := spec[hardForkName]
	if !exists {
		return 0, fmt.Errorf("%s version not known by chain", hardForkName)
	}
	epoch, isEpoch := tmp.(uint64)
	if !isEpoch {
		return 0, fmt.Errorf("%s is not a uint64", hardForkName)
	}

	return phase0.Epoch(epoch), nil
}
