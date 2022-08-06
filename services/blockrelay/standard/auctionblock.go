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

package standard

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/attestantio/go-block-relay/services/blockauctioneer"
	builderclient "github.com/attestantio/go-builder-client"
	builderspec "github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
)

// AuctionBlock obtains the best available use of the block space.
func (s *Service) AuctionBlock(ctx context.Context,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
) (
	*blockauctioneer.Results,
	error,
) {
	res, err := s.bestBuilderBid(ctx, slot, parentHash, pubkey)
	if err != nil {
		return nil, err
	}

	if res.Bid != nil {
		key := fmt.Sprintf("%d", slot)
		subKey := fmt.Sprintf("%x:%x", parentHash, pubkey)
		s.builderBidsCacheMu.Lock()
		if _, exists := s.builderBidsCache[key]; !exists {
			s.builderBidsCache[key] = make(map[string]*builderspec.VersionedSignedBuilderBid)
		}
		s.builderBidsCache[key][subKey] = res.Bid
		s.builderBidsCacheMu.Unlock()
	}

	return res, nil
}

type builderBidResponse struct {
	provider builderclient.BuilderBidProvider
	bid      *builderspec.VersionedSignedBuilderBid
	score    *big.Int
}

// bestBuilderBid provides the best builder bid from a number of relays.
func (s *Service) bestBuilderBid(ctx context.Context,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
) (
	*blockauctioneer.Results,
	error,
) {
	started := time.Now()
	log := util.LogWithID(ctx, log, "strategy_id").With().Uint64("slot", uint64(slot)).Logger()

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)

	res := &blockauctioneer.Results{
		Values: make(map[string]*big.Int),
	}

	respCh := make(chan *builderBidResponse, len(s.builderBidProviders))
	errCh := make(chan error, len(s.builderBidProviders))
	// Kick off the requests.
	for _, provider := range s.builderBidProviders {
		go s.builderBid(ctx, started, provider, respCh, errCh, slot, parentHash, pubkey)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	timedOut := 0
	bestScore := new(big.Int)
	bidsMu := new(sync.Mutex)

	for responded+errored+timedOut != len(s.builderBidProviders) {
		select {
		case <-softCtx.Done():
			// If we have any responses at this point we consider the non-responders timed out.
			if responded > 0 {
				timedOut = len(s.builderBidProviders) - responded - errored
				log.Debug().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Msg("Soft timeout reached with responses")
			} else {
				log.Debug().Dur("elapsed", time.Since(started)).Int("errored", errored).Msg("Soft timeout reached with no responses")
			}
		case <-ctx.Done():
			// Anyone not responded by now is considered errored.
			timedOut = len(s.builderBidProviders) - responded - errored
			log.Debug().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Hard timeout reached")
		case err := <-errCh:
			errored++
			log.Debug().Dur("elapsed", time.Since(started)).Err(err).Msg("Responded with error")
		case resp := <-respCh:
			responded++
			if res.Bid == nil || resp.score.Cmp(bestScore) > 0 {
				res.Bid = resp.bid
				bestScore = resp.score
				res.Provider = resp.provider
			}
			bidsMu.Lock()
			res.Values[resp.provider.Address()] = resp.score
			bidsMu.Unlock()
		}
	}
	softCancel()
	cancel()
	log.Trace().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Responses")

	if res.Bid == nil {
		monitorAuctionBlock("", false, time.Since(started))
		return nil, errors.New("no bids received")
	}
	log.Trace().Stringer("bid", res.Bid).Msg("Selected best bid")
	monitorAuctionBlock(res.Provider.Address(), true, time.Since(started))

	return res, nil
}

func (s *Service) builderBid(ctx context.Context,
	started time.Time,
	provider builderclient.BuilderBidProvider,
	respCh chan *builderBidResponse,
	errCh chan error,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
) {
	log := log.With().Str("bidder", provider.Address()).Logger()
	builderBid, err := provider.BuilderBid(ctx, slot, parentHash, pubkey)
	if err != nil {
		errCh <- errors.Wrap(err, provider.Address())
		return
	}
	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(builderBid)
		if err != nil {
			errCh <- errors.Wrap(err, provider.Address())
			return
		}
		e.RawJSON("builder_bid", data).Msg("Obtained builder bid")
	}
	if builderBid.IsEmpty() {
		errCh <- fmt.Errorf("%s: builder bid empty", provider.Address())
		return
	}
	switch builderBid.Version {
	case consensusspec.DataVersionBellatrix:
		if builderBid.Data == nil {
			errCh <- fmt.Errorf("%s: data missing", provider.Address())
			return
		}
		if builderBid.Data.Message == nil {
			errCh <- fmt.Errorf("%s: data message missing", provider.Address())
			return
		}
		if builderBid.Data.Message.Header == nil {
			errCh <- fmt.Errorf("%s: data message header missing", provider.Address())
			return
		}
	default:
		errCh <- fmt.Errorf("%s: unhandled builder bid data verison %v", provider.Address(), builderBid.Version)
	}

	respCh <- &builderBidResponse{
		bid:      builderBid,
		provider: provider,
		score:    builderBid.Data.Message.Value.ToBig(),
	}
}
