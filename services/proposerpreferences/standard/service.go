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
	stderrors "errors"
	"net/http"
	"sync"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/proposerpreferences"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is the standard proposer-preferences service.
type Service struct {
	log            zerolog.Logger
	monitor        metrics.Service
	cache          map[gloas.ProposerPreferences]*cachedPreference
	current        map[preferenceDuty]gloas.ProposerPreferences
	dependentRoots map[phase0.Slot]phase0.Root
	inFlight       map[gloas.ProposerPreferences]chan struct{}
	signer         signer.ProposerPreferencesSigner
	submitter      submitter.ProposerPreferencesSubmitter
	unsupported    map[string]phase0.Epoch
	pendingConfig  map[phase0.ValidatorIndex]preferenceConfig
	reportedConfig map[preferenceConfig]struct{}
	firstApplied   map[preferenceConfig]phase0.Slot
	mutex          sync.Mutex
}

type preferenceConfig struct {
	feeRecipient bellatrix.ExecutionAddress
	gasLimit     uint64
}

func configOf(preferences gloas.ProposerPreferences) preferenceConfig {
	return preferenceConfig{feeRecipient: preferences.FeeRecipient, gasLimit: preferences.TargetGasLimit}
}

type preferenceDuty struct {
	proposalSlot   phase0.Slot
	validatorIndex phase0.ValidatorIndex
}

type cachedPreference struct {
	accepted       map[string]struct{}
	outcomes       map[string]error
	attempted      map[string]phase0.Slot
	attemptedEpoch map[string]phase0.Epoch
	signed         *gloas.SignedProposerPreferences
	published      bool
}

type publication struct {
	preferences  gloas.ProposerPreferences
	cached       *cachedPreference
	providers    []string
	sign         bool
	attemptSlot  phase0.Slot
	attemptEpoch phase0.Epoch
	complete     chan struct{}
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
		log:            zerologger.With().Str("service", "proposerpreferences").Logger(),
		unsupported:    make(map[string]phase0.Epoch),
		pendingConfig:  make(map[phase0.ValidatorIndex]preferenceConfig),
		reportedConfig: make(map[preferenceConfig]struct{}),
		firstApplied:   make(map[preferenceConfig]phase0.Slot),
		signer:         parameters.signer,
		submitter:      parameters.submitter,
		cache:          make(map[gloas.ProposerPreferences]*cachedPreference),
		current:        make(map[preferenceDuty]gloas.ProposerPreferences),
		dependentRoots: make(map[phase0.Slot]phase0.Root),
		inFlight:       make(map[gloas.ProposerPreferences]chan struct{}),
	}, nil
}

// FlushConfigChangeWarnings reports config changes after all duties in this publication run were inspected.
func (s *Service) FlushConfigChangeWarnings() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for config, slot := range s.firstApplied {
		if _, reported := s.reportedConfig[config]; reported {
			continue
		}
		count := 0
		for _, pending := range s.pendingConfig {
			if pending == config {
				count++
			}
		}
		if count > 0 {
			s.log.Warn().Int("affected_validators", count).Uint64("first_slot", uint64(slot)).Msg("Proposer preferences config change delayed")
			s.reportedConfig[config] = struct{}{}
		}
	}
	clear(s.firstApplied)
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
	s.clearPendingWithoutSignedDuties(0)
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
	s.clearPendingWithoutSignedDuties(slot)
}

// clearPendingWithoutSignedDuties discards config changes with no still-relevant signed preference.
// The caller holds s.mutex.
func (s *Service) clearPendingWithoutSignedDuties(fromSlot phase0.Slot) {
	for index := range s.pendingConfig {
		future := false
		for duty, preferences := range s.current {
			if duty.validatorIndex == index && duty.proposalSlot >= fromSlot {
				cached := s.cache[preferences]
				if cached != nil && cached.signed != nil {
					future = true
					break
				}
			}
		}
		if !future {
			delete(s.pendingConfig, index)
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
		publication, complete := s.claimPublication(preferences, dutyKey, duty.CurrentSlot, duty.CurrentEpoch)
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

func (s *Service) claimPublication(preferences gloas.ProposerPreferences, dutyKey preferenceDuty, currentSlot phase0.Slot, currentEpoch phase0.Epoch) (*publication, chan struct{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if currentSlot >= dutyKey.proposalSlot {
		return nil, nil
	}
	if dependentRoot, exists := s.dependentRoots[dutyKey.proposalSlot]; exists && dependentRoot != preferences.DependentRoot {
		monitorProposerPreferencesProcess("stale")
		return nil, nil
	}
	if current, exists := s.current[dutyKey]; exists && current.DependentRoot == preferences.DependentRoot {
		if cached := s.cache[current]; cached != nil && cached.signed != nil {
			if configOf(current) != configOf(preferences) {
				if previous, pending := s.pendingConfig[dutyKey.validatorIndex]; pending && previous != configOf(preferences) {
					delete(s.reportedConfig, previous)
				}
				s.pendingConfig[dutyKey.validatorIndex] = configOf(preferences)
			} else {
				delete(s.pendingConfig, dutyKey.validatorIndex)
			}
		}
		preferences = current
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
	providers := s.failedProviders(cached, currentSlot, currentEpoch)
	if exists && len(providers) == 0 {
		return nil, nil
	}
	complete := make(chan struct{})
	s.inFlight[preferences] = complete
	if !exists {
		cached = &cachedPreference{
			accepted:       make(map[string]struct{}),
			outcomes:       make(map[string]error),
			attempted:      make(map[string]phase0.Slot),
			attemptedEpoch: make(map[string]phase0.Epoch),
		}
		s.cache[preferences] = cached
	}
	s.current[dutyKey] = preferences

	return &publication{
		preferences:  preferences,
		cached:       cached,
		complete:     complete,
		providers:    providers,
		sign:         !exists,
		attemptSlot:  currentSlot,
		attemptEpoch: currentEpoch,
	}, nil
}

func (s *Service) failedProviders(cached *cachedPreference, currentSlot phase0.Slot, currentEpoch phase0.Epoch) []string {
	if cached == nil {
		return nil
	}
	providers := make([]string, 0)
	for provider, err := range cached.outcomes {
		if err != nil && cached.attempted[provider] != currentSlot {
			if !routeMissing(cached.outcomes[provider]) || cached.attemptedEpoch[provider] != currentEpoch {
				providers = append(providers, provider)
			}
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
	s.recordSignedConfig(publication.preferences)

	return nil
}

func (s *Service) recordSignedConfig(preferences gloas.ProposerPreferences) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	config := configOf(preferences)
	if slot, exists := s.firstApplied[config]; !exists || preferences.ProposalSlot < slot {
		s.firstApplied[config] = preferences.ProposalSlot
	}
}

func (s *Service) abandonPublication(publication *publication) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.cache, publication.preferences)
	delete(s.inFlight, publication.preferences)
	close(publication.complete)
}

func routeMissing(err error) bool {
	var apiErr *api.Error
	return stderrors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusMethodNotAllowed || apiErr.StatusCode == http.StatusNotImplemented)
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
		publication.cached.attempted[provider] = publication.attemptSlot
		publication.cached.attemptedEpoch[provider] = publication.attemptEpoch
		if err == nil {
			if _, unsupported := s.unsupported[provider]; unsupported {
				delete(s.unsupported, provider)
				s.log.Info().Str("provider", provider).Msg("Proposer preferences provider recovered")
			}
		} else {
			if routeMissing(err) {
				if _, unsupported := s.unsupported[provider]; !unsupported {
					var apiErr *api.Error
					stderrors.As(err, &apiErr)
					s.log.Warn().Str("provider", provider).Int("status_code", apiErr.StatusCode).Msg("Proposer preferences provider does not support submission route")
				}
				s.unsupported[provider] = publication.attemptEpoch
			}
		}
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
		// Failing providers are retried on the next publication; only fail when none accepted.
		if len(publication.cached.accepted) > 0 {
			return nil
		}

		return errors.Wrap(submissionErr, "failed to submit proposer preferences")
	}
	publication.cached.published = len(s.failedProviders(publication.cached, publication.attemptSlot+1, publication.attemptEpoch+1)) == 0

	return nil
}
