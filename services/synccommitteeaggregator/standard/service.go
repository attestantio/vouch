// Copyright © 2021, 2024 Attestant Limited.
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
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/synccommitteeaggregator"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
)

// Service is a sync committee aggregator.
type Service struct {
	log                                  zerolog.Logger
	monitor                              metrics.Service
	slotsPerEpoch                        uint64
	syncCommitteeSize                    uint64
	syncCommitteeSubnetCount             uint64
	targetAggregatorsPerSyncSubcommittee uint64
	beaconBlockRootProvider              eth2client.BeaconBlockRootProvider
	contributionAndProofSigner           signer.ContributionAndProofSigner
	validatingAccountsProvider           accountmanager.ValidatingAccountsProvider
	syncCommitteeContributionProvider    eth2client.SyncCommitteeContributionProvider
	syncCommitteeContributionsSubmitter  eth2client.SyncCommitteeContributionsSubmitter
	beaconBlockRoots                     map[phase0.Slot]phase0.Root
	beaconBlockRootsMu                   sync.Mutex
	chainTime                            chaintime.Service
}

// New creates a new sync committee aggregator.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "synccommitteeaggregator").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}

	specResponse, err := parameters.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	tmp, exists := spec["SLOTS_PER_EPOCH"]
	if !exists {
		return nil, errors.New("SLOTS_PER_EPOCH not found in spec")
	}
	slotsPerEpoch, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("SLOTS_PER_EPOCH of unexpected type")
	}

	tmp, exists = spec["SYNC_COMMITTEE_SIZE"]
	if !exists {
		return nil, errors.New("SYNC_COMMITTEE_SIZE not found in spec")
	}
	syncCommitteeSize, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("SYNC_COMMITTEE_SIZE of unexpected type")
	}

	tmp, exists = spec["SYNC_COMMITTEE_SUBNET_COUNT"]
	if !exists {
		return nil, errors.New("SYNC_COMMITTEE_SUBNET_COUNT not found in spec")
	}
	syncCommitteeSubnetCount, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("SYNC_COMMITTEE_SUBNET_COUNT of unexpected type")
	}

	tmp, exists = spec["TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE"]
	if !exists {
		return nil, errors.New("TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE not found in spec")
	}
	targetAggregatorsPerSyncSubcommittee, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE of unexpected type")
	}

	s := &Service{
		log:                                  log,
		monitor:                              parameters.monitor,
		slotsPerEpoch:                        slotsPerEpoch,
		syncCommitteeSize:                    syncCommitteeSize,
		syncCommitteeSubnetCount:             syncCommitteeSubnetCount,
		targetAggregatorsPerSyncSubcommittee: targetAggregatorsPerSyncSubcommittee,
		beaconBlockRootProvider:              parameters.beaconBlockRootProvider,
		contributionAndProofSigner:           parameters.contributionAndProofSigner,
		validatingAccountsProvider:           parameters.validatingAccountsProvider,
		syncCommitteeContributionProvider:    parameters.syncCommitteeContributionProvider,
		syncCommitteeContributionsSubmitter:  parameters.syncCommitteeContributionsSubmitter,
		beaconBlockRoots:                     map[phase0.Slot]phase0.Root{},
		chainTime:                            parameters.chainTime,
	}

	return s, nil
}

// SetBeaconBlockRoot sets the beacon block root used for a given slot.
// Set by the sync committee messenger when it is creating the messages for the slot.
func (s *Service) SetBeaconBlockRoot(slot phase0.Slot, root phase0.Root) {
	s.beaconBlockRootsMu.Lock()
	s.beaconBlockRoots[slot] = root
	s.beaconBlockRootsMu.Unlock()
}

// Aggregate aggregates the attestations for a given slot/committee combination.
func (s *Service) Aggregate(ctx context.Context, duty *synccommitteeaggregator.Duty) {
	ctx, span := otel.Tracer("attestantio.vouch.services.synccommitteeaggregator.standard").Start(ctx, "Aggregate")
	defer span.End()
	started := time.Now()

	log := s.log.With().Uint64("slot", uint64(duty.Slot)).Int("validators", len(duty.ValidatorIndices)).Logger()
	log.Trace().Msg("Aggregating")

	var beaconBlockRoot *phase0.Root

	startOfSlot := s.chainTime.StartOfSlot(duty.Slot)
	s.beaconBlockRootsMu.Lock()
	if tmp, exists := s.beaconBlockRoots[duty.Slot]; exists {
		beaconBlockRoot = &tmp
		delete(s.beaconBlockRoots, duty.Slot)
		s.beaconBlockRootsMu.Unlock()
		log.Trace().Msg("Obtained beacon block root from cache")
	} else {
		s.beaconBlockRootsMu.Unlock()
		log.Debug().Msg("Failed to obtain beacon block root from cache; using head")
		beaconBlockRootResponse, err := s.beaconBlockRootProvider.BeaconBlockRoot(ctx, &api.BeaconBlockRootOpts{
			Block: "head",
		})
		if err != nil {
			log.Warn().Err(err).Msg("Failed to obtain beacon block root")
			monitorSyncCommitteeAggregationsCompleted(started, duty.Slot, len(duty.ValidatorIndices), "failed", startOfSlot)
			return
		}
		beaconBlockRoot = beaconBlockRootResponse.Data
	}
	log.Trace().Dur("elapsed", time.Since(started)).Str("beacon_block_root", fmt.Sprintf("%#x", *beaconBlockRoot)).Msg("Obtained beacon block root")

	contributionAndProofs := make([]*altair.ContributionAndProof, 0)
	accounts := make([]e2wtypes.Account, 0)
	for _, validatorIndex := range duty.ValidatorIndices {
		for subcommitteeIndex := range duty.SelectionProofs[validatorIndex] {
			log.Trace().Uint64("validator_index", uint64(validatorIndex)).Uint64("subcommittee_index", subcommitteeIndex).Str("beacon_block_root", fmt.Sprintf("%#x", *beaconBlockRoot)).Msg("Aggregating")
			contributionResponse, err := s.syncCommitteeContributionProvider.SyncCommitteeContribution(ctx, &api.SyncCommitteeContributionOpts{
				Slot:              duty.Slot,
				SubcommitteeIndex: subcommitteeIndex,
				BeaconBlockRoot:   *beaconBlockRoot,
			})
			if err != nil {
				log.Warn().Err(err).Msg("Failed to obtain sync committee contribution")
				monitorSyncCommitteeAggregationsCompleted(started, duty.Slot, len(duty.ValidatorIndices), "failed", startOfSlot)
				return
			}
			contribution := contributionResponse.Data
			contributionAndProof := &altair.ContributionAndProof{
				AggregatorIndex: validatorIndex,
				Contribution:    contribution,
				SelectionProof:  duty.SelectionProofs[validatorIndex][subcommitteeIndex],
			}
			contributionAndProofs = append(contributionAndProofs, contributionAndProof)
			account, exists := duty.Accounts[validatorIndex]
			if !exists {
				log.Debug().Msg("Account nil; likely exited validator still in sync committee")
				monitorSyncCommitteeAggregationsCompleted(started, duty.Slot, len(duty.ValidatorIndices), "exited", startOfSlot)
				return
			}
			accounts = append(accounts, account)
		}
	}

	sigs, err := s.contributionAndProofSigner.SignContributionAndProofs(ctx, accounts, contributionAndProofs)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain signatures of contribution and proofs")
		monitorSyncCommitteeAggregationsCompleted(started, duty.Slot, len(duty.ValidatorIndices), "failed", startOfSlot)
		return
	}

	signedContributionAndProofs := make([]*altair.SignedContributionAndProof, 0)
	for i := range sigs {
		signedContributionAndProof := &altair.SignedContributionAndProof{
			Message:   contributionAndProofs[i],
			Signature: sigs[i],
		}
		signedContributionAndProofs = append(signedContributionAndProofs, signedContributionAndProof)
	}

	if err := s.syncCommitteeContributionsSubmitter.SubmitSyncCommitteeContributions(ctx, signedContributionAndProofs); err != nil {
		log.Warn().Err(err).Msg("Failed to submit signed contribution and proofs")
		monitorSyncCommitteeAggregationsCompleted(started, duty.Slot, len(signedContributionAndProofs), "failed", startOfSlot)
		return
	}

	log.Trace().Msg("Submitted signed contribution and proofs")
	for i := range signedContributionAndProofs {
		frac := float64(signedContributionAndProofs[i].Message.Contribution.AggregationBits.Count()) /
			float64(signedContributionAndProofs[i].Message.Contribution.AggregationBits.Len())
		monitorSyncCommitteeAggregationCoverage(frac)
	}
	monitorSyncCommitteeAggregationsCompleted(started, duty.Slot, len(signedContributionAndProofs), "succeeded", startOfSlot)
}
