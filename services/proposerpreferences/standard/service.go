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

// Package standard provides the standard proposer-preferences service.
package standard

import (
	"context"
	"sync"

	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/proposerpreferences"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is the standard proposer-preferences service.
type Service struct {
	monitor        metrics.Service
	cache          map[gloas.ProposerPreferences]*cachedPreference
	current        map[preferenceDuty]gloas.ProposerPreferences
	dependentRoots map[phase0.Slot]phase0.Root
	inFlight       map[gloas.ProposerPreferences]chan struct{}
	signer         signer.ProposerPreferencesSigner
	submitter      submitter.ProposerPreferencesSubmitter
	mutex          sync.Mutex
}

type preferenceDuty struct {
	proposalSlot   phase0.Slot
	validatorIndex phase0.ValidatorIndex
}

type cachedPreference struct {
	accepted  map[string]struct{}
	outcomes  map[string]error
	signed    *gloas.SignedProposerPreferences
	published bool
}

type publication struct {
	preferences gloas.ProposerPreferences
	cached      *cachedPreference
	providers   []string
	sign        bool
	complete    chan struct{}
}

// New creates a standard proposer-preferences service.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}
	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.Wrap(err, "failed to register metrics")
	}

	return &Service{
		monitor:        parameters.monitor,
		signer:         parameters.signer,
		submitter:      parameters.submitter,
		cache:          make(map[gloas.ProposerPreferences]*cachedPreference),
		current:        make(map[preferenceDuty]gloas.ProposerPreferences),
		dependentRoots: make(map[phase0.Slot]phase0.Root),
		inFlight:       make(map[gloas.ProposerPreferences]chan struct{}),
	}, nil
}

// ProviderReady reports whether provider has accepted the current preference for a proposal duty.
func (s *Service) ProviderReady(provider string, proposalSlot phase0.Slot, validatorIndex phase0.ValidatorIndex) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	preferences, exists := s.current[preferenceDuty{proposalSlot: proposalSlot, validatorIndex: validatorIndex}]
	if !exists {
		return false
	}
	cached, exists := s.cache[preferences]
	if !exists {
		return false
	}
	if provider == "simple" {
		return cached.published
	}
	_, exists = cached.accepted[provider]

	return exists
}

// UpdateDependentRoot updates the authoritative root for proposer duties in the supplied slot range.
func (s *Service) UpdateDependentRoot(fromSlot phase0.Slot, toSlot phase0.Slot, root phase0.Root) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for slot := fromSlot; slot <= toSlot; slot++ {
		s.dependentRoots[slot] = root
	}
	for duty, preferences := range s.current {
		if duty.proposalSlot >= fromSlot && duty.proposalSlot <= toSlot && preferences.DependentRoot != root {
			delete(s.current, duty)
		}
	}
}

// Prune discards preferences for proposal slots that have passed.
func (s *Service) Prune(slot phase0.Slot) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for duty, preferences := range s.current {
		if duty.proposalSlot < slot {
			if _, exists := s.inFlight[preferences]; !exists {
				delete(s.current, duty)
			}
		}
	}
	for proposalSlot := range s.dependentRoots {
		if proposalSlot < slot {
			delete(s.dependentRoots, proposalSlot)
		}
	}
	for preferences := range s.cache {
		if preferences.ProposalSlot < slot {
			if _, exists := s.inFlight[preferences]; !exists {
				delete(s.cache, preferences)
			}
		}
	}
}

// Publish publishes the supplied duty's proposer preferences.
func (s *Service) Publish(ctx context.Context, duty *proposerpreferences.Duty) error {
	if duty == nil {
		return errors.New("no proposer preferences duty supplied")
	}
	if duty.Account == nil {
		return errors.New("no account supplied for proposer preferences duty")
	}

	preferences := gloas.ProposerPreferences{
		DependentRoot:  duty.DependentRoot,
		ProposalSlot:   duty.ProposalSlot,
		ValidatorIndex: duty.ValidatorIndex,
		FeeRecipient:   duty.FeeRecipient,
		TargetGasLimit: duty.TargetGasLimit,
	}
	dutyKey := preferenceDuty{proposalSlot: duty.ProposalSlot, validatorIndex: duty.ValidatorIndex}
	for {
		publication, complete := s.claimPublication(preferences, dutyKey)
		if publication != nil {
			return s.publish(ctx, duty.Account, publication)
		}
		if complete == nil {
			return nil
		}
		if err := waitForPublication(ctx, complete); err != nil {
			return err
		}
	}
}

func (s *Service) claimPublication(preferences gloas.ProposerPreferences, dutyKey preferenceDuty) (*publication, chan struct{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if dependentRoot, exists := s.dependentRoots[dutyKey.proposalSlot]; exists && dependentRoot != preferences.DependentRoot {
		monitorProposerPreferencesProcess("stale")
		return nil, nil
	}
	cached, exists := s.cache[preferences]
	if exists && cached.published {
		s.current[dutyKey] = preferences
		monitorProposerPreferencesProcess("replayed")
		return nil, nil
	}
	if complete, exists := s.inFlight[preferences]; exists {
		return nil, complete
	}
	complete := make(chan struct{})
	s.inFlight[preferences] = complete
	if current, exists := s.current[dutyKey]; exists && current != preferences {
		monitorProposerPreferencesProcess("refreshed")
	}
	providers := failedProviders(cached)
	if !exists {
		cached = &cachedPreference{
			accepted: make(map[string]struct{}),
			outcomes: make(map[string]error),
		}
		s.cache[preferences] = cached
	}
	s.current[dutyKey] = preferences

	return &publication{
		preferences: preferences,
		cached:      cached,
		complete:    complete,
		providers:   providers,
		sign:        !exists,
	}, nil
}

func failedProviders(cached *cachedPreference) []string {
	if cached == nil {
		return nil
	}
	providers := make([]string, 0)
	for provider, err := range cached.outcomes {
		if err != nil {
			providers = append(providers, provider)
		}
	}

	return providers
}

func waitForPublication(ctx context.Context, complete <-chan struct{}) error {
	select {
	case <-complete:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) publish(ctx context.Context, account e2wtypes.Account, publication *publication) error {
	if publication.sign {
		if err := s.sign(ctx, account, publication); err != nil {
			return err
		}
	}

	outcomes := s.submitter.SubmitProposerPreferences(ctx, []*gloas.SignedProposerPreferences{publication.cached.signed}, publication.providers)

	return s.recordSubmission(publication, outcomes)
}

func (s *Service) sign(ctx context.Context, account e2wtypes.Account, publication *publication) error {
	signature, err := s.signer.SignProposerPreferences(ctx, account, &publication.preferences)
	if err != nil {
		s.abandonPublication(publication)
		return errors.Wrap(err, "failed to sign proposer preferences")
	}
	publication.cached.signed = &gloas.SignedProposerPreferences{
		Message:   &publication.preferences,
		Signature: signature,
	}
	monitorProposerPreferencesProcess("signed")

	return nil
}

func (s *Service) abandonPublication(publication *publication) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.cache, publication.preferences)
	delete(s.inFlight, publication.preferences)
	close(publication.complete)
}

func (s *Service) recordSubmission(publication *publication, outcomes map[string]error) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	defer close(publication.complete)
	defer delete(s.inFlight, publication.preferences)

	if len(outcomes) == 0 {
		return errors.New("no proposer preferences submission outcomes")
	}
	var submissionErr error
	for provider, err := range outcomes {
		publication.cached.outcomes[provider] = err
		if err == nil {
			publication.cached.accepted[provider] = struct{}{}
			monitorProposerPreferencesProcess("accepted")
			continue
		}
		delete(publication.cached.accepted, provider)
		monitorProposerPreferencesProcess("rejected")
		if submissionErr == nil {
			submissionErr = err
		}
	}
	if submissionErr != nil {
		return errors.Wrap(submissionErr, "failed to submit proposer preferences")
	}
	publication.cached.published = true

	return nil
}
