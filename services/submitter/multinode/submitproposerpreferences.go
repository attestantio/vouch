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

package multinode

import (
	"context"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/pkg/errors"
	"golang.org/x/sync/semaphore"
)

// SubmitProposerPreferences submits signed proposer preferences to every configured beacon node.
func (s *Service) SubmitProposerPreferences(ctx context.Context, preferences []*gloas.SignedProposerPreferences) map[string]error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.timeout)
	defer cancel()

	outcomes := make(map[string]error, len(s.proposerPreferencesSubmitters))
	if len(preferences) == 0 {
		for name := range s.proposerPreferencesSubmitters {
			outcomes[name] = errors.New("no proposer preferences supplied")
		}
		return outcomes
	}

	sem := semaphore.NewWeighted(s.processConcurrency)
	var outcomesMutex sync.Mutex
	var wg sync.WaitGroup
	for name, submitter := range s.proposerPreferencesSubmitters {
		wg.Go(func() {
			s.submitProposerPreferences(ctx, sem, &outcomesMutex, outcomes, name, preferences, submitter)
		})
	}
	wg.Wait()

	return outcomes
}

func (s *Service) submitProposerPreferences(ctx context.Context,
	sem *semaphore.Weighted,
	outcomesMutex *sync.Mutex,
	outcomes map[string]error,
	name string,
	preferences []*gloas.SignedProposerPreferences,
	submitter eth2client.ProposerPreferencesSubmitter,
) {
	log := s.log.With().Str("beacon_node_address", name).Logger()
	if err := sem.Acquire(ctx, 1); err != nil {
		outcomesMutex.Lock()
		outcomes[name] = err
		outcomesMutex.Unlock()
		log.Warn().Err(err).Msg("Failed to acquire semaphore")
		return
	}
	defer sem.Release(1)

	_, address := s.serviceInfo(ctx, submitter)
	started := time.Now()
	err := submitter.SubmitProposerPreferences(ctx, preferences)
	s.clientMonitor.ClientOperation(address, "submit proposer preferences", err == nil, time.Since(started))

	outcomesMutex.Lock()
	outcomes[name] = err
	outcomesMutex.Unlock()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to submit proposer preferences")
		return
	}
	log.Trace().Msg("Submitted proposer preferences")
}
