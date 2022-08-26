// Copyright © 2022 Attestant Limited.
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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
)

var zeroFeeRecipient bellatrix.ExecutionAddress

type beaconBlockResponse struct {
	provider string
	proposal *api.VersionedBlindedBeaconBlock
	score    float64
}

// BlindedBeaconBlockProposal provides the best blinded beacon block proposal from a number of beacon nodes.
func (s *Service) BlindedBeaconBlockProposal(ctx context.Context, slot phase0.Slot, randaoReveal phase0.BLSSignature, graffiti []byte) (*api.VersionedBlindedBeaconBlock, error) {
	started := time.Now()
	log := util.LogWithID(ctx, log, "strategy_id").With().Uint64("slot", uint64(slot)).Logger()

	requests := len(s.blindedBeaconBlockProposalProviders)

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)

	respCh := make(chan *beaconBlockResponse, requests)
	errCh := make(chan error, requests)
	// Kick off the requests.
	for name, provider := range s.blindedBeaconBlockProposalProviders {
		providerGraffiti := graffiti
		if bytes.Contains(providerGraffiti, []byte("{{CLIENT}}")) {
			if nodeClientProvider, isProvider := provider.(eth2client.NodeClientProvider); isProvider {
				nodeClient, err := nodeClientProvider.NodeClient(ctx)
				if err != nil {
					log.Warn().Err(err).Msg("Failed to obtain node client; not updating graffiti")
				} else {
					providerGraffiti = bytes.ReplaceAll(providerGraffiti, []byte("{{CLIENT}}"), []byte(nodeClient))
				}
			}
		}
		if len(providerGraffiti) > 32 {
			providerGraffiti = providerGraffiti[0:32]
		}
		go s.blindedBeaconBlockProposal(ctx, started, name, provider, respCh, errCh, slot, randaoReveal, providerGraffiti)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	timedOut := 0
	softTimedOut := 0
	bestScore := float64(0)
	var bestProposal *api.VersionedBlindedBeaconBlock
	bestProvider := ""

	// Loop 1: prior to soft timeout.
	for responded+errored+timedOut+softTimedOut != requests {
		select {
		case resp := <-respCh:
			responded++
			log.Trace().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Response received")
			if bestProposal == nil || resp.score > bestScore {
				bestProposal = resp.proposal
				bestScore = resp.score
				bestProvider = resp.provider
			}
		case err := <-errCh:
			errored++
			log.Debug().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Err(err).Msg("Error received")
		case <-softCtx.Done():
			// If we have any responses at this point we consider the non-responders timed out.
			if responded > 0 {
				timedOut = requests - responded - errored
				log.Debug().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Soft timeout reached with responses")
			} else {
				log.Debug().Dur("elapsed", time.Since(started)).Int("errored", errored).Msg("Soft timeout reached with no responses")
			}
			// Set the number of requests that have soft timed out.
			softTimedOut = requests - responded - errored - timedOut
		}
	}
	softCancel()

	// Loop 2: after soft timeout.
	for responded+errored+timedOut != requests {
		select {
		case resp := <-respCh:
			responded++
			log.Trace().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Response received")
			if bestProposal == nil || resp.score > bestScore {
				bestProposal = resp.proposal
				bestScore = resp.score
				bestProvider = resp.provider
			}
		case err := <-errCh:
			errored++
			log.Debug().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Err(err).Msg("Error received")
		case <-ctx.Done():
			// Anyone not responded by now is considered errored.
			timedOut = requests - responded - errored
			log.Debug().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Hard timeout reached")
		}
	}
	cancel()
	log.Trace().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Responses")

	if bestProposal == nil {
		return nil, errors.New("no proposals received")
	}
	log.Trace().Stringer("proposal", bestProposal).Float64("score", bestScore).Msg("Selected best proposal")
	if bestProvider != "" {
		s.clientMonitor.StrategyOperation("best", bestProvider, "blinded beacon block proposal", time.Since(started))
	}

	return bestProposal, nil
}

func (s *Service) blindedBeaconBlockProposal(ctx context.Context,
	started time.Time,
	name string,
	provider eth2client.BlindedBeaconBlockProposalProvider,
	respCh chan *beaconBlockResponse,
	errCh chan error,
	slot phase0.Slot,
	randaoReveal phase0.BLSSignature,
	graffiti []byte,
) {
	proposal, err := provider.BlindedBeaconBlockProposal(ctx, slot, randaoReveal, graffiti)
	s.clientMonitor.ClientOperation(name, "blinded beacon block proposal", err == nil, time.Since(started))
	if err != nil {
		errCh <- errors.Wrap(err, name)
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained blinded beacon block proposal")
	if proposal == nil {
		errCh <- errors.New("empty blinded beacon block response")
		return
	}
	feeRecipient, err := proposal.FeeRecipient()
	if err != nil {
		errCh <- errors.Wrap(err, "failed to obtain blinded beacon block fee recipient")
		return
	}
	if bytes.Equal(feeRecipient[:], zeroFeeRecipient[:]) {
		errCh <- errors.New("blinded beacon block response has 0 fee recipient")
		return
	}

	score := s.scoreBlindedBeaconBlockProposal(ctx, name, proposal)
	respCh <- &beaconBlockResponse{
		provider: name,
		proposal: proposal,
		score:    score,
	}
}
