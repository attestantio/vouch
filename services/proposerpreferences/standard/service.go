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
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/proposerpreferences"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
)

// Service is the standard proposer-preferences service.
type Service struct {
	monitor   metrics.Service
	cache     map[gloas.ProposerPreferences]*cachedPreference
	signer    signer.ProposerPreferencesSigner
	submitter submitter.ProposerPreferencesSubmitter
	mutex     sync.Mutex
}

type cachedPreference struct {
	signed    *gloas.SignedProposerPreferences
	published bool
}

// New creates a standard proposer-preferences service.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	return &Service{
		monitor:   parameters.monitor,
		signer:    parameters.signer,
		submitter: parameters.submitter,
		cache:     make(map[gloas.ProposerPreferences]*cachedPreference),
	}, nil
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

	s.mutex.Lock()
	defer s.mutex.Unlock()
	cached, exists := s.cache[preferences]
	if exists && cached.published {
		return nil
	}
	if !exists {
		signature, err := s.signer.SignProposerPreferences(ctx, duty.Account, &preferences)
		if err != nil {
			return errors.Wrap(err, "failed to sign proposer preferences")
		}
		cached = &cachedPreference{signed: &gloas.SignedProposerPreferences{
			Message:   &preferences,
			Signature: signature,
		}}
		s.cache[preferences] = cached
	}

	outcomes := s.submitter.SubmitProposerPreferences(ctx, []*gloas.SignedProposerPreferences{cached.signed})
	if len(outcomes) == 0 {
		return errors.New("no proposer preferences submission outcomes")
	}
	for _, err := range outcomes {
		if err != nil {
			return errors.Wrap(err, "failed to submit proposer preferences")
		}
	}
	cached.published = true

	return nil
}
