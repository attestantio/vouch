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
	"context"
	"fmt"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
)

type beaconBlockResponse struct {
	provider string
	proposal *spec.VersionedBeaconBlock
	score    float64
}

// BeaconBlockProposal provides the best beacon block proposal from a number of beacon nodes.
func (s *Service) BeaconBlockProposal(ctx context.Context, slot phase0.Slot, randaoReveal phase0.BLSSignature, graffiti []byte) (*spec.VersionedBeaconBlock, error) {
	started := time.Now()
	log := util.LogWithID(ctx, log, "strategy_id").With().Uint64("slot", uint64(slot)).Logger()

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)

	respCh := make(chan *beaconBlockResponse, len(s.beaconBlockProposalProviders))
	errCh := make(chan error, len(s.beaconBlockProposalProviders))
	// Kick off the requests.
	for name, provider := range s.beaconBlockProposalProviders {
		go s.beaconBlockProposal(ctx, started, name, provider, respCh, errCh, slot, randaoReveal, graffiti)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	timedOut := 0
	bestScore := float64(0)
	var bestProposal *spec.VersionedBeaconBlock
	bestProvider := ""

	for responded+errored+timedOut != len(s.beaconBlockProposalProviders) {
		select {
		case <-softCtx.Done():
			// If we have any responses at this point we consider the non-responders timed out.
			if responded > 0 {
				timedOut = len(s.beaconBlockProposalProviders) - responded - errored
				log.Debug().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Msg("Soft timeout reached with responses")
			} else {
				log.Debug().Dur("elapsed", time.Since(started)).Int("errored", errored).Msg("Soft timeout reached with no responses")
			}
		case <-ctx.Done():
			// Anyone not responded by now is considered errored.
			timedOut = len(s.beaconBlockProposalProviders) - responded - errored
			log.Debug().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Hard timeout reached")
		case err := <-errCh:
			errored++
			log.Debug().Dur("elapsed", time.Since(started)).Err(err).Msg("Responded with error")
		case resp := <-respCh:
			responded++
			if bestProposal == nil || resp.score > bestScore {
				bestProposal = resp.proposal
				bestScore = resp.score
				bestProvider = resp.provider
			}
		}
	}
	softCancel()
	cancel()
	log.Trace().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Responses")

	if bestProposal == nil {
		return nil, errors.New("no proposals received")
	}
	log.Trace().Stringer("proposal", bestProposal).Float64("score", bestScore).Msg("Selected best proposal")
	if bestProvider != "" {
		s.clientMonitor.StrategyOperation("best", bestProvider, "beacon block proposal", time.Since(started))
	}

	return bestProposal, nil
}

func (s *Service) beaconBlockProposal(ctx context.Context,
	started time.Time,
	name string,
	provider eth2client.BeaconBlockProposalProvider,
	respCh chan *beaconBlockResponse,
	errCh chan error,
	slot phase0.Slot,
	randaoReveal phase0.BLSSignature,
	graffiti []byte,
) {
	proposal, err := provider.BeaconBlockProposal(ctx, slot, randaoReveal, graffiti)
	s.clientMonitor.ClientOperation(name, "beacon block proposal", err == nil, time.Since(started))
	if err != nil {
		errCh <- errors.Wrap(err, name)
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained attestation data")
	if proposal == nil {
		return
	}

	// Obtain the slot of the block to which the proposal refers.
	// We use this to allow the scorer to score blocks with earlier parents lower.
	parentRoot, err := proposal.ParentRoot()
	if err != nil {
		log.Error().Str("version", proposal.Version.String()).Msg("Failed to obtain parent root")
		return
	}
	var parentSlot phase0.Slot
	parentBlock, err := s.signedBeaconBlockProvider.SignedBeaconBlock(ctx, fmt.Sprintf("%#x", parentRoot[:]))
	switch {
	case err != nil:
		log.Warn().Err(err).Msg("Failed to obtain parent block")
		slot, err := proposal.Slot()
		if err != nil {
			log.Error().Str("version", proposal.Version.String()).Err(err).Msg("Failed to obtain proposal slot")
		}
		parentSlot = slot - 1
	case parentBlock == nil:
		log.Warn().Msg("Empty parent block")
		slot, err := proposal.Slot()
		if err != nil {
			log.Error().Str("version", proposal.Version.String()).Err(err).Msg("Failed to obtain proposal slot")
		}
		parentSlot = slot - 1
	default:
		slot, err := parentBlock.Slot()
		if err != nil {
			log.Error().Str("version", proposal.Version.String()).Err(err).Msg("Failed to obtain proposal slot for parent block")
		}
		parentSlot = slot
	}

	score := s.scoreBeaconBlockProposal(ctx, name, parentSlot, proposal)
	respCh <- &beaconBlockResponse{
		provider: name,
		proposal: proposal,
		score:    score,
	}
}
