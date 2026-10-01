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

	log := zerologger.With().Str("service", "proposerpreferences").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	return &Service{
		monitor:        parameters.monitor,
		log:            log,
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
// Callers ask only about builder-backed proposals, so a false answer is recorded as a rejected builder bid.
func (s *Service) ProviderReady(provider string, proposalSlot phase0.Slot, validatorIndex phase0.ValidatorIndex) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.providerReady(provider, proposalSlot, validatorIndex) {
		return true
	}
	monitorProposerPreferencesProvider(provider, "builder_bid_rejected")

	return false
}

// providerReady reports readiness.  The caller holds s.mutex.
func (s *Service) providerReady(provider string, proposalSlot phase0.Slot, validatorIndex phase0.ValidatorIndex) bool {
	preferences, exists := s.current[preferenceDuty{proposalSlot: proposalSlot, validatorIndex: validatorIndex}]
	if !exists {
		return false
	}
	cached, exists := s.cache[preferences]
	if !exists {
		return false
	}
	if provider == proposerpreferences.SimpleProvider {
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
			s.dropPendingConfig(index)
		}
	}
}

// dropPendingConfig discards a validator's config change, and its report once no validator has it pending.
// The caller holds s.mutex.
func (s *Service) dropPendingConfig(index phase0.ValidatorIndex) {
	config, exists := s.pendingConfig[index]
	if !exists {
		return
	}
	delete(s.pendingConfig, index)
	for _, pending := range s.pendingConfig {
		if pending == config {
			return
		}
	}
	delete(s.reportedConfig, config)
}

// Publish publishes the supplied duty's proposer preferences.
// It returns an error only if no provider has accepted the preferences.
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
	preferences = s.firstSignedPreference(preferences, dutyKey)
	cached, exists := s.cache[preferences]
	if exists && cached.published {
		s.current[dutyKey] = preferences
		monitorProposerPreferencesProcess("replayed")
		return nil, nil
	}
	if complete, exists := s.inFlight[preferences]; exists {
		return nil, complete
	}
	providers := failedProviders(cached, s.unsupported, currentSlot, currentEpoch)
	if exists && len(providers) == 0 {
		s.current[dutyKey] = preferences
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

// firstSignedPreference retains the first signature and tracks config changes for later duties.
// The caller holds s.mutex.
func (s *Service) firstSignedPreference(preferences gloas.ProposerPreferences, dutyKey preferenceDuty) gloas.ProposerPreferences {
	current, exists := s.current[dutyKey]
	cached := s.cache[current]
	if !exists || current.DependentRoot != preferences.DependentRoot || cached == nil {
		return preferences
	}
	if cached.signed != nil {
		if configOf(current) != configOf(preferences) {
			if s.pendingConfig[dutyKey.validatorIndex] != configOf(preferences) {
				s.dropPendingConfig(dutyKey.validatorIndex)
			}
			s.pendingConfig[dutyKey.validatorIndex] = configOf(preferences)
		} else {
			s.dropPendingConfig(dutyKey.validatorIndex)
		}
	}
	return current
}

// failedProviders returns providers to retry this slot.  Route-missing failures are retried once per epoch while the provider is unsupported.
func failedProviders(cached *cachedPreference, unsupported map[string]phase0.Epoch, currentSlot phase0.Slot, currentEpoch phase0.Epoch) []string {
	if cached == nil {
		return nil
	}
	providers := make([]string, 0)
	for provider, err := range cached.outcomes {
		if err != nil && cached.attempted[provider] != currentSlot {
			_, stillUnsupported := unsupported[provider]
			if !routeMissing(err) || !stillUnsupported || cached.attemptedEpoch[provider] != currentEpoch {
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
		monitorProposerPreferencesProcess("cancelled")
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
		if errors.Is(err, signer.ErrProposerPreferencesDomainUnavailable) {
			monitorProposerPreferencesProcess("domain_unavailable")
		} else {
			monitorProposerPreferencesProcess("sign_failed")
		}
		return errors.Wrap(err, "failed to sign proposer preferences")
	}
	monitorProposerPreferencesProcess("signed")
	s.recordSignature(publication, signature)

	return nil
}

func (s *Service) recordSignature(publication *publication, signature phase0.BLSSignature) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	publication.cached.signed = &gloas.SignedProposerPreferences{
		Message:   &publication.preferences,
		Signature: signature,
	}
	config := configOf(publication.preferences)
	if pending, exists := s.pendingConfig[publication.preferences.ValidatorIndex]; !exists || pending != config {
		return
	}
	if slot, exists := s.firstApplied[config]; !exists || publication.preferences.ProposalSlot < slot {
		s.firstApplied[config] = publication.preferences.ProposalSlot
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
		monitorProposerPreferencesProcess("no_outcomes")
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
			monitorProposerPreferencesProvider(provider, "accepted")
			continue
		}
		delete(publication.cached.accepted, provider)
		monitorProposerPreferencesProcess("rejected")
		monitorProposerPreferencesProvider(provider, "rejected")
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
	publication.cached.published = len(failedProviders(publication.cached, s.unsupported, publication.attemptSlot+1, publication.attemptEpoch+1)) == 0

	return nil
}
