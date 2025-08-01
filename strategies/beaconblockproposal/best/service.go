// Copyright © 2020 - 2025 Attestant Limited.
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

package best

import (
	"context"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/cache"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the provider for beacon block proposals.
type Service struct {
	log                       zerolog.Logger
	clientMonitor             metrics.ClientMonitor
	processConcurrency        int64
	chainTime                 chaintime.Service
	proposalProviders         map[string]eth2client.ProposalProvider
	signedBeaconBlockProvider eth2client.SignedBeaconBlockProvider
	timeout                   time.Duration
	blockRootToSlotCache      cache.BlockRootToSlotProvider
	executionPayloadFactor    float64

	// Spec values for scoring proposals.
	slotsPerEpoch      uint64
	timelySourceWeight uint64
	timelyTargetWeight uint64
	timelyHeadWeight   uint64
	syncRewardWeight   uint64
	proposerWeight     uint64
	weightDenominator  uint64

	priorBlocksVotes   map[phase0.Root]*priorBlockVotes
	priorBlocksVotesMu sync.RWMutex
}

type priorBlockVotes struct {
	root   phase0.Root
	parent phase0.Root
	slot   phase0.Slot
	// votes is a map of attestation slot -> committee index -> votes.
	votes map[phase0.Slot]map[phase0.CommitteeIndex]bitfield.Bitlist
}

type proposalScoringMetrics struct {
	slotsPerEpoch      uint64
	timelySourceWeight uint64
	timelyTargetWeight uint64
	timelyHeadWeight   uint64
	syncRewardWeight   uint64
	proposerWeight     uint64
	weightDenominator  uint64
}

// New creates a new beacon block proposal strategy.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("strategy", "beaconblockproposal").Str("impl", "best").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	specResponse, err := parameters.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	scoringData, err := extractProposalScoringData(spec)
	if err != nil {
		return nil, err
	}

	s := &Service{
		log:                       log,
		processConcurrency:        parameters.processConcurrency,
		chainTime:                 parameters.chainTime,
		proposalProviders:         parameters.proposalProviders,
		signedBeaconBlockProvider: parameters.signedBeaconBlockProvider,
		timeout:                   parameters.timeout,
		blockRootToSlotCache:      parameters.blockRootToSlotCache,
		clientMonitor:             parameters.clientMonitor,
		slotsPerEpoch:             scoringData.slotsPerEpoch,
		timelySourceWeight:        scoringData.timelySourceWeight,
		timelyTargetWeight:        scoringData.timelyTargetWeight,
		timelyHeadWeight:          scoringData.timelyHeadWeight,
		syncRewardWeight:          scoringData.syncRewardWeight,
		proposerWeight:            scoringData.proposerWeight,
		weightDenominator:         scoringData.weightDenominator,
		priorBlocksVotes:          make(map[phase0.Root]*priorBlockVotes),
		executionPayloadFactor:    parameters.executionPayloadFactor,
	}
	log.Trace().Int64("process_concurrency", s.processConcurrency).Msg("Set process concurrency")

	// Subscribe to head events.  This allows us to go early for attestations if a block arrives, as well as
	// re-request duties if there is a change in beacon block.
	// This also allows us to re-request duties if the dependent roots change.
	if err := parameters.eventsProvider.Events(ctx, &api.EventsOpts{
		Topics:      []string{"head"},
		HeadHandler: s.HandleHeadEvent,
	}); err != nil {
		return nil, errors.Wrap(err, "failed to add head event handler")
	}

	return s, nil
}

func extractProposalScoringData(spec map[string]any) (*proposalScoringMetrics, error) {
	tmp, exists := spec["SLOTS_PER_EPOCH"]
	if !exists {
		return nil, errors.New("failed to obtain SLOTS_PER_EPOCH")
	}
	slotsPerEpoch, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("SLOTS_PER_EPOCH of unexpected type")
	}

	tmp, exists = spec["TIMELY_SOURCE_WEIGHT"]
	if !exists {
		// Set a default value based on the Altair spec.
		tmp = uint64(14)
	}
	timelySourceWeight, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("TIMELY_SOURCE_WEIGHT of unexpected type")
	}

	tmp, exists = spec["TIMELY_TARGET_WEIGHT"]
	if !exists {
		// Set a default value based on the Altair spec.
		tmp = uint64(26)
	}
	timelyTargetWeight, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("TIMELY_TARGET_WEIGHT of unexpected type")
	}

	tmp, exists = spec["TIMELY_HEAD_WEIGHT"]
	if !exists {
		// Set a default value based on the Altair spec.
		tmp = uint64(14)
	}
	timelyHeadWeight, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("TIMELY_HEAD_WEIGHT of unexpected type")
	}

	tmp, exists = spec["SYNC_REWARD_WEIGHT"]
	if !exists {
		// Set a default value based on the Altair spec.
		tmp = uint64(2)
	}
	syncRewardWeight, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("SYNC_REWARD_WEIGHT of unexpected type")
	}

	tmp, exists = spec["PROPOSER_WEIGHT"]
	if !exists {
		// Set a default value based on the Altair spec.
		tmp = uint64(8)
	}
	proposerWeight, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("PROPOSER_WEIGHT of unexpected type")
	}

	tmp, exists = spec["WEIGHT_DENOMINATOR"]
	if !exists {
		// Set a default value based on the Altair spec.
		tmp = uint64(64)
	}
	weightDenominator, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("WEIGHT_DENOMINATOR of unexpected type")
	}
	scoringMetrics := &proposalScoringMetrics{
		slotsPerEpoch:      slotsPerEpoch,
		timelySourceWeight: timelySourceWeight,
		timelyTargetWeight: timelyTargetWeight,
		timelyHeadWeight:   timelyHeadWeight,
		syncRewardWeight:   syncRewardWeight,
		proposerWeight:     proposerWeight,
		weightDenominator:  weightDenominator,
	}
	return scoringMetrics, nil
}
