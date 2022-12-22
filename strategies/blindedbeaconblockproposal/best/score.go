// Copyright © 2020 - 2022 Attestant Limited.
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
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/attestantio/go-eth2-client/api"
	apiv1bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	apiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
)

// scoreBlindedBeaconBlockPropsal generates a score for a blinded beacon block.
// The score is relative to the reward expected by proposing the block.
func (s *Service) scoreBlindedBeaconBlockProposal(ctx context.Context,
	name string,
	blockProposal *api.VersionedBlindedBeaconBlock,
) float64 {
	if blockProposal == nil {
		return 0
	}
	if blockProposal.IsEmpty() {
		return 0
	}

	// Obtain the slot of the block to which the proposal refers.
	// We use this to allow the scorer to score blocks with earlier parents lower.
	parentRoot, err := blockProposal.ParentRoot()
	if err != nil {
		log.Error().Str("version", blockProposal.Version.String()).Msg("Failed to obtain parent root")
		return 0
	}
	parentSlot, err := s.blockRootToSlotCache.BlockRootToSlot(ctx, parentRoot)
	if err != nil {
		log.Debug().Str("root", fmt.Sprintf("%#x", parentRoot)).Err(err).Msg("Failed to obtain parent slot; assuming 0")
		parentSlot = 0
	}

	switch blockProposal.Version {
	case spec.DataVersionBellatrix:
		return s.scoreBellatrixBlindedBeaconBlockProposal(ctx, name, parentSlot, blockProposal.Bellatrix)
	case spec.DataVersionCapella:
		return s.scoreCapellaBlindedBeaconBlockProposal(ctx, name, parentSlot, blockProposal.Capella)
	default:
		log.Error().Int("version", int(blockProposal.Version)).Msg("Unhandled block version")
		return 0
	}
}

// scoreBellatrixBlindedBeaconBlockPropsal generates a score for a bellatrix blinded beacon block.
func (s *Service) scoreBellatrixBlindedBeaconBlockProposal(ctx context.Context,
	name string,
	parentSlot phase0.Slot,
	blockProposal *apiv1bellatrix.BlindedBeaconBlock,
) float64 {
	attestationScore := float64(0)
	immediateAttestationScore := float64(0)

	// We need to avoid duplicates in attestations.
	// Map is attestation slot -> committee index -> validator committee index -> aggregate.
	attested := make(map[phase0.Slot]map[phase0.CommitteeIndex]bitfield.Bitlist)
	for _, attestation := range blockProposal.Body.Attestations {
		data := attestation.Data
		if _, exists := attested[data.Slot]; !exists {
			attested[data.Slot] = make(map[phase0.CommitteeIndex]bitfield.Bitlist)
		}
		if _, exists := attested[data.Slot][data.Index]; !exists {
			if !exists {
				attested[data.Slot][data.Index] = bitfield.NewBitlist(attestation.AggregationBits.Len())
			}
		}

		priorVotes, err := s.priorVotesForAttestation(ctx, attestation, blockProposal.ParentRoot)
		if err != nil {
			log.Debug().Err(err).Msg("Failed to obtain prior votes for attestation; assuming no votes")
		}

		votes := 0
		for i := uint64(0); i < attestation.AggregationBits.Len(); i++ {
			if attestation.AggregationBits.BitAt(i) {
				if attested[attestation.Data.Slot][attestation.Data.Index].BitAt(i) {
					// Already attested in this block; skip.
					continue
				}
				if priorVotes.BitAt(i) {
					// Attested in a previous block; skip.
					continue
				}
				votes++
				attested[attestation.Data.Slot][attestation.Data.Index].SetBitAt(i, true)
			}
		}

		// Now we know how many new votes are in this attestation we can score it.
		// We can calculate if the head vote is correct, but not target so for the
		// purposes of the calculation we assume that it is.

		headCorrect := bellatrixHeadCorrect(blockProposal, attestation)
		targetCorrect := s.bellatrixTargetCorrect(ctx, attestation)
		inclusionDistance := blockProposal.Slot - attestation.Data.Slot

		score := 0.0
		if targetCorrect {
			// Target is correct (and timely).
			score += float64(s.timelyTargetWeight) / float64(s.weightDenominator)
		}
		if inclusionDistance <= 5 {
			// Source is timely.
			score += float64(s.timelySourceWeight) / float64(s.weightDenominator)
		}
		if headCorrect && inclusionDistance == 1 {
			score += float64(s.timelyHeadWeight) / float64(s.weightDenominator)
		}
		score *= float64(votes)
		attestationScore += score
		if inclusionDistance == 1 {
			immediateAttestationScore += score
		}
	}

	attesterSlashingScore, proposerSlashingScore := scoreSlashings(blockProposal.Body.AttesterSlashings, blockProposal.Body.ProposerSlashings)

	// Add sync committee score.
	syncCommitteeScore := float64(blockProposal.Body.SyncAggregate.SyncCommitteeBits.Count()) * float64(s.syncRewardWeight) / float64(s.weightDenominator)

	log.Trace().
		Uint64("slot", uint64(blockProposal.Slot)).
		Uint64("parent_slot", uint64(parentSlot)).
		Str("provider", name).
		Float64("immediate_attestations", immediateAttestationScore).
		Float64("attestations", attestationScore).
		Float64("proposer_slashings", proposerSlashingScore).
		Float64("attester_slashings", attesterSlashingScore).
		Float64("sync_committee", syncCommitteeScore).
		Float64("total", attestationScore+proposerSlashingScore+attesterSlashingScore+syncCommitteeScore).
		Msg("Scored Bellatrix block")

	return attestationScore + proposerSlashingScore + attesterSlashingScore + syncCommitteeScore
}

// scoreCapellaBlindedBeaconBlockPropsal generates a score for a capella blinded beacon block.
func (s *Service) scoreCapellaBlindedBeaconBlockProposal(ctx context.Context,
	name string,
	parentSlot phase0.Slot,
	blockProposal *apiv1capella.BlindedBeaconBlock,
) float64 {
	attestationScore := float64(0)
	immediateAttestationScore := float64(0)

	// We need to avoid duplicates in attestations.
	// Map is attestation slot -> committee index -> validator committee index -> aggregate.
	attested := make(map[phase0.Slot]map[phase0.CommitteeIndex]bitfield.Bitlist)
	for _, attestation := range blockProposal.Body.Attestations {
		data := attestation.Data
		if _, exists := attested[data.Slot]; !exists {
			attested[data.Slot] = make(map[phase0.CommitteeIndex]bitfield.Bitlist)
		}
		if _, exists := attested[data.Slot][data.Index]; !exists {
			if !exists {
				attested[data.Slot][data.Index] = bitfield.NewBitlist(attestation.AggregationBits.Len())
			}
		}

		priorVotes, err := s.priorVotesForAttestation(ctx, attestation, blockProposal.ParentRoot)
		if err != nil {
			log.Debug().Err(err).Msg("Failed to obtain prior votes for attestation; assuming no votes")
		}

		votes := 0
		for i := uint64(0); i < attestation.AggregationBits.Len(); i++ {
			if attestation.AggregationBits.BitAt(i) {
				if attested[attestation.Data.Slot][attestation.Data.Index].BitAt(i) {
					// Already attested in this block; skip.
					continue
				}
				if priorVotes.BitAt(i) {
					// Attested in a previous block; skip.
					continue
				}
				votes++
				attested[attestation.Data.Slot][attestation.Data.Index].SetBitAt(i, true)
			}
		}

		// Now we know how many new votes are in this attestation we can score it.
		// We can calculate if the head vote is correct, but not target so for the
		// purposes of the calculation we assume that it is.

		headCorrect := capellaHeadCorrect(blockProposal, attestation)
		targetCorrect := s.bellatrixTargetCorrect(ctx, attestation)
		inclusionDistance := blockProposal.Slot - attestation.Data.Slot

		score := 0.0
		if targetCorrect {
			// Target is correct (and timely).
			score += float64(s.timelyTargetWeight) / float64(s.weightDenominator)
		}
		if inclusionDistance <= 5 {
			// Source is timely.
			score += float64(s.timelySourceWeight) / float64(s.weightDenominator)
		}
		if headCorrect && inclusionDistance == 1 {
			score += float64(s.timelyHeadWeight) / float64(s.weightDenominator)
		}
		score *= float64(votes)
		attestationScore += score
		if inclusionDistance == 1 {
			immediateAttestationScore += score
		}
	}

	attesterSlashingScore, proposerSlashingScore := scoreSlashings(blockProposal.Body.AttesterSlashings, blockProposal.Body.ProposerSlashings)

	// Add sync committee score.
	syncCommitteeScore := float64(blockProposal.Body.SyncAggregate.SyncCommitteeBits.Count()) * float64(s.syncRewardWeight) / float64(s.weightDenominator)

	log.Trace().
		Uint64("slot", uint64(blockProposal.Slot)).
		Uint64("parent_slot", uint64(parentSlot)).
		Str("provider", name).
		Float64("immediate_attestations", immediateAttestationScore).
		Float64("attestations", attestationScore).
		Float64("proposer_slashings", proposerSlashingScore).
		Float64("attester_slashings", attesterSlashingScore).
		Float64("sync_committee", syncCommitteeScore).
		Float64("total", attestationScore+proposerSlashingScore+attesterSlashingScore+syncCommitteeScore).
		Msg("Scored Capella block")

	return attestationScore + proposerSlashingScore + attesterSlashingScore + syncCommitteeScore
}

func scoreSlashings(attesterSlashings []*phase0.AttesterSlashing,
	proposerSlashings []*phase0.ProposerSlashing,
) (float64, float64) {
	// Slashing reward will be at most MAX_EFFECTIVE_BALANCE/WHISTLEBLOWER_REWARD_QUOTIENT,
	// which is 0.0625 Ether.
	// Individual attestation reward at 250K validators will be around 23,000 GWei, or .000023 Ether.
	// So we state that a single slashing event has the same weight as about 2,700 attestations.
	slashingWeight := float64(2700)

	// Add proposer slashing scores.
	proposerSlashingScore := float64(len(proposerSlashings)) * slashingWeight

	// Add attester slashing scores.
	indicesSlashed := 0
	for _, slashing := range attesterSlashings {
		indicesSlashed += len(intersection(slashing.Attestation1.AttestingIndices, slashing.Attestation2.AttestingIndices))
	}
	attesterSlashingScore := slashingWeight * float64(indicesSlashed)

	return attesterSlashingScore, proposerSlashingScore
}

func (s *Service) priorVotesForAttestation(_ context.Context,
	attestation *phase0.Attestation,
	root phase0.Root,
) (
	bitfield.Bitlist,
	error,
) {
	var res bitfield.Bitlist
	var err error
	found := false
	s.priorBlocksVotesMu.RLock()
	for {
		priorBlock, exists := s.priorBlocksVotes[root]
		if !exists {
			// This means we do not have a parent block.
			break
		}
		if priorBlock.slot < attestation.Data.Slot-phase0.Slot(s.slotsPerEpoch) {
			// Block is too far back for its attestations to count.
			break
		}

		slotVotes, exists := priorBlock.votes[attestation.Data.Slot]
		if exists {
			votes, exists := slotVotes[attestation.Data.Index]
			if exists {
				if !found {
					res = bitfield.NewBitlist(votes.Len())
					found = true
				}
				res, err = res.Or(votes)
				if err != nil {
					return bitfield.Bitlist{}, err
				}
			}
		}

		root = priorBlock.parent
	}
	s.priorBlocksVotesMu.RUnlock()

	if !found {
		// No prior votes found, return an empty list.
		return bitfield.NewBitlist(attestation.AggregationBits.Len()), nil
	}

	return res, nil
}

func (s *Service) bellatrixTargetCorrect(_ context.Context,
	attestation *phase0.Attestation,
) bool {
	s.priorBlocksVotesMu.RLock()
	defer s.priorBlocksVotesMu.RUnlock()
	root := attestation.Data.BeaconBlockRoot
	maxSlot := s.chainTime.FirstSlotOfEpoch(attestation.Data.Target.Epoch)
	for {
		priorBlock, exists := s.priorBlocksVotes[root]
		if !exists {
			// We don't have data on this block, assume the target is correct.
			// (We could assume the target is incorrect in this situation, but that
			// would give false incorrects whilst the prior block cache warms up.)
			log.Trace().Uint64("attestation_slot", uint64(attestation.Data.Slot)).Uint64("max_slot", uint64(maxSlot)).Str("root", fmt.Sprintf("%#x", root)).Msg("Root does not exist, assuming true")
			return true
		}
		if priorBlock.slot <= maxSlot {
			return bytes.Equal(attestation.Data.Target.Root[:], priorBlock.root[:])
		}
		root = priorBlock.parent
	}
}

// bellatrixHeadCorrect calculates if the head of a Bellatrix attestation is correct.
func bellatrixHeadCorrect(blockProposal *apiv1bellatrix.BlindedBeaconBlock, attestation *phase0.Attestation) bool {
	return bytes.Equal(blockProposal.ParentRoot[:], attestation.Data.BeaconBlockRoot[:])
}

// capellaHeadCorrect calculates if the head of a Capella attestation is correct.
func capellaHeadCorrect(blockProposal *apiv1capella.BlindedBeaconBlock, attestation *phase0.Attestation) bool {
	return bytes.Equal(blockProposal.ParentRoot[:], attestation.Data.BeaconBlockRoot[:])
}

// intersection returns a list of items common between the two sets.
func intersection(set1 []uint64, set2 []uint64) []uint64 {
	sort.Slice(set1, func(i, j int) bool { return set1[i] < set1[j] })
	sort.Slice(set2, func(i, j int) bool { return set2[i] < set2[j] })
	res := make([]uint64, 0)

	set1Pos := 0
	set2Pos := 0
	for set1Pos < len(set1) && set2Pos < len(set2) {
		switch {
		case set1[set1Pos] < set2[set2Pos]:
			set1Pos++
		case set2[set2Pos] < set1[set1Pos]:
			set2Pos++
		default:
			res = append(res, set1[set1Pos])
			set1Pos++
			set2Pos++
		}
	}

	return res
}
