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
	"maps"
	"strings"
	"sync/atomic"
	"time"

	client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// forkSchedule is immutable after publication through Service.forkSchedule.
type forkSchedule struct {
	epochs    map[string]phase0.Epoch
	malformed map[string]struct{}
}

type forkScheduleRefresh struct {
	err  error
	done chan struct{}
}

type forkScheduleGeneration struct {
	refresh atomic.Pointer[forkScheduleRefresh]
}

// Service provides chain time services.
type Service struct {
	log                    zerolog.Logger
	specProvider           client.SpecProvider
	genesisTime            time.Time
	slotDuration           time.Duration
	slotsPerEpoch          uint64
	forkSchedule           atomic.Pointer[forkSchedule]
	forkScheduleGeneration atomic.Pointer[forkScheduleGeneration]
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
	forkSchedule := forkScheduleFromSpec(spec)
	s.forkSchedule.Store(&forkSchedule)
	s.forkScheduleGeneration.Store(&forkScheduleGeneration{})

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
	forkSchedule := s.forkSchedule.Load()
	if forkEpoch, exists := forkSchedule.epochs[hardForkName]; exists {
		return forkEpoch
	}
	if _, exists := forkSchedule.malformed[hardForkName]; exists {
		s.log.Error().Err(fmt.Errorf("%s is not a uint64", hardForkName)).Msg("Failed to obtain hard fork")
		return 0xffffffffffffffff
	}

	generation := s.forkScheduleGeneration.Load()
	forkSchedule = s.forkSchedule.Load()
	if forkEpoch, exists := forkSchedule.epochs[hardForkName]; exists {
		return forkEpoch
	}
	if _, exists := forkSchedule.malformed[hardForkName]; exists {
		s.log.Error().Err(fmt.Errorf("%s is not a uint64", hardForkName)).Msg("Failed to obtain hard fork")
		return 0xffffffffffffffff
	}
	if err := s.refreshForkSchedule(ctx, generation); err != nil {
		s.log.Error().Err(err).Msg("Failed to obtain hard fork")
		return 0xffffffffffffffff
	}
	forkSchedule = s.forkSchedule.Load()
	if forkEpoch, exists := forkSchedule.epochs[hardForkName]; exists {
		return forkEpoch
	}
	if _, exists := forkSchedule.malformed[hardForkName]; exists {
		s.log.Error().Err(fmt.Errorf("%s is not a uint64", hardForkName)).Msg("Failed to obtain hard fork")
		return 0xffffffffffffffff
	}

	s.log.Error().Err(fmt.Errorf("%s version not known by chain", hardForkName)).Msg("Failed to obtain hard fork")
	return 0xffffffffffffffff
}

func forkScheduleFromSpec(spec map[string]any) forkSchedule {
	res := forkSchedule{
		epochs:    make(map[string]phase0.Epoch),
		malformed: make(map[string]struct{}),
	}
	for name, value := range spec {
		if !strings.HasSuffix(name, "_FORK_EPOCH") {
			continue
		}
		epoch, isEpoch := value.(uint64)
		if !isEpoch {
			res.malformed[name] = struct{}{}
			continue
		}
		res.epochs[name] = phase0.Epoch(epoch)
	}

	return res
}

func (s *Service) refreshForkSchedule(ctx context.Context, generation *forkScheduleGeneration) error {
	if generation == nil {
		generation = &forkScheduleGeneration{}
		if !s.forkScheduleGeneration.CompareAndSwap(nil, generation) {
			generation = s.forkScheduleGeneration.Load()
		}
	}

	refresh := generation.refresh.Load()
	leader := false
	if refresh == nil {
		candidate := &forkScheduleRefresh{done: make(chan struct{})}
		if generation.refresh.CompareAndSwap(nil, candidate) {
			refresh = candidate
			leader = true
		} else {
			refresh = generation.refresh.Load()
		}
	}
	if !leader {
		select {
		case <-refresh.done:
			return refresh.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	specResponse, err := s.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		err = errors.Wrap(err, "failed to obtain spec")
	} else {
		current := s.forkSchedule.Load()
		incoming := forkScheduleFromSpec(specResponse.Data)
		var next *forkSchedule
		cloneCurrent := func() {
			if next == nil {
				next = &forkSchedule{
					epochs:    maps.Clone(current.epochs),
					malformed: maps.Clone(current.malformed),
				}
			}
		}
		for name, epoch := range incoming.epochs {
			if currentEpoch, exists := current.epochs[name]; exists {
				if currentEpoch == epoch {
					continue
				}
				now := s.CurrentEpoch()
				if currentEpoch <= now || epoch <= now {
					continue
				}
			}
			cloneCurrent()
			next.epochs[name] = epoch
			delete(next.malformed, name)
		}
		for name := range incoming.malformed {
			if _, exists := current.epochs[name]; exists {
				continue
			}
			if _, exists := current.malformed[name]; exists {
				continue
			}
			cloneCurrent()
			next.malformed[name] = struct{}{}
		}
		if next != nil {
			s.forkSchedule.Store(next)
		}
	}

	refresh.err = err
	s.forkScheduleGeneration.CompareAndSwap(generation, &forkScheduleGeneration{})
	close(refresh.done)

	return err
}
