// Copyright © 2026 Attestant Limited.
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
	"sort"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/proposerpreferences"
	"github.com/attestantio/vouch/util"
)

// recordProposerPreferencesDependentRoot retains the root used to derive proposer duties for an epoch.
func (s *Service) recordProposerPreferencesDependentRoot(epoch phase0.Epoch, root phase0.Root) {
	if root == (phase0.Root{}) {
		return
	}
	s.proposerPreferencesDependentRootMutex.Lock()
	defer s.proposerPreferencesDependentRootMutex.Unlock()
	if s.proposerPreferencesDependentRoots == nil {
		s.proposerPreferencesDependentRoots = make(map[phase0.Epoch]phase0.Root)
	}
	s.proposerPreferencesDependentRoots[epoch] = root
	for storedEpoch := range s.proposerPreferencesDependentRoots {
		if storedEpoch+phase0.Epoch(s.proposerPreferencesLookahead) < s.chainTimeService.CurrentEpoch() {
			delete(s.proposerPreferencesDependentRoots, storedEpoch)
		}
	}
}

func (s *Service) queueProposerPreferencesPublication(ctx context.Context) {
	s.proposerPreferencesPublicationMutex.Lock()
	s.proposerPreferencesPublicationPending = true
	if s.proposerPreferencesPublicationRunning {
		s.proposerPreferencesPublicationMutex.Unlock()
		return
	}
	s.proposerPreferencesPublicationRunning = true
	s.proposerPreferencesPublicationMutex.Unlock()

	go func() {
		for {
			s.proposerPreferencesPublicationMutex.Lock()
			s.proposerPreferencesPublicationPending = false
			s.proposerPreferencesPublicationMutex.Unlock()

			s.publishProposerPreferencesForKnownRoots(ctx)

			s.proposerPreferencesPublicationMutex.Lock()
			if !s.proposerPreferencesPublicationPending {
				s.proposerPreferencesPublicationRunning = false
				s.proposerPreferencesPublicationMutex.Unlock()
				return
			}
			s.proposerPreferencesPublicationMutex.Unlock()
		}
	}()
}

// publishProposerPreferencesForKnownRoots publishes each recorded root whose lookahead target has not passed.
func (s *Service) publishProposerPreferencesForKnownRoots(ctx context.Context) {
	s.proposerPreferencesDependentRootMutex.RLock()
	epochs := make([]phase0.Epoch, 0, len(s.proposerPreferencesDependentRoots))
	roots := make(map[phase0.Epoch]phase0.Root, len(s.proposerPreferencesDependentRoots))
	for epoch, root := range s.proposerPreferencesDependentRoots {
		epochs = append(epochs, epoch)
		roots[epoch] = root
	}
	s.proposerPreferencesDependentRootMutex.RUnlock()
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
	for _, epoch := range epochs {
		s.publishProposerPreferences(ctx, epoch, roots[epoch])
	}
}

// publishProposerPreferences publishes preferences for the proposal epoch whose duties share the supplied dependent root.
func (s *Service) publishProposerPreferences(ctx context.Context, rootEpoch phase0.Epoch, dependentRoot phase0.Root) {
	if dependentRoot == (phase0.Root{}) || s.proposerPreferences == nil || s.executionConfigProvider == nil || s.proposerPreferencesLookahead == 0 {
		return
	}

	proposalEpoch := rootEpoch + phase0.Epoch(s.proposerPreferencesLookahead)
	if proposalEpoch < s.gloasForkEpoch || proposalEpoch < s.chainTimeService.CurrentEpoch() {
		return
	}

	response, err := s.proposerDutiesProvider.ProposerDuties(ctx, &api.ProposerDutiesOpts{Epoch: proposalEpoch})
	if err != nil {
		s.log.Error().Err(err).Uint64("epoch", uint64(proposalEpoch)).Msg("Failed to fetch proposer preferences duties")
		return
	}
	if response == nil || len(response.Data) == 0 {
		return
	}
	responseDependentRoot, ok := response.Metadata["dependent_root"].(phase0.Root)
	if !ok || responseDependentRoot == (phase0.Root{}) {
		s.log.Error().Uint64("epoch", uint64(proposalEpoch)).Msg("No dependent root for proposer preferences duties")
		return
	}

	firstSlot := s.chainTimeService.FirstSlotOfEpoch(proposalEpoch)
	lastSlot := s.chainTimeService.FirstSlotOfEpoch(proposalEpoch+1) - 1
	currentSlot := s.chainTimeService.CurrentSlot()
	duties := make([]*apiv1.ProposerDuty, 0, len(response.Data))
	indices := make([]phase0.ValidatorIndex, 0, len(response.Data))
	seenIndices := make(map[phase0.ValidatorIndex]struct{})
	for _, duty := range response.Data {
		if duty == nil || duty.Slot < firstSlot || duty.Slot > lastSlot || duty.Slot <= currentSlot {
			continue
		}
		duties = append(duties, duty)
		if _, exists := seenIndices[duty.ValidatorIndex]; !exists {
			seenIndices[duty.ValidatorIndex] = struct{}{}
			indices = append(indices, duty.ValidatorIndex)
		}
	}
	if len(duties) == 0 {
		return
	}

	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, proposalEpoch, indices)
	if err != nil {
		s.log.Error().Err(err).Uint64("epoch", uint64(proposalEpoch)).Msg("Failed to obtain proposer preferences accounts")
		return
	}
	for _, duty := range duties {
		account, exists := accounts[duty.ValidatorIndex]
		if !exists {
			s.log.Error().Uint64("validator_index", uint64(duty.ValidatorIndex)).Msg("No account for proposer preferences duty")
			continue
		}
		config, err := s.executionConfigProvider.ProposerConfig(ctx, account, util.ValidatorPubkey(account))
		if err != nil {
			s.log.Error().Err(err).Uint64("validator_index", uint64(duty.ValidatorIndex)).Msg("Failed to obtain proposer preferences execution configuration")
			continue
		}
		if config == nil {
			s.log.Error().Uint64("validator_index", uint64(duty.ValidatorIndex)).Msg("No proposer preferences execution configuration")
			continue
		}
		if err := s.proposerPreferences.Publish(ctx, proposerpreferences.NewDuty(
			responseDependentRoot,
			duty.Slot,
			duty.ValidatorIndex,
			account,
			config.FeeRecipient,
			config.GasLimit,
		)); err != nil {
			s.log.Error().Err(err).Uint64("proposal_slot", uint64(duty.Slot)).Msg("Failed to publish proposer preferences")
		}
	}
}
