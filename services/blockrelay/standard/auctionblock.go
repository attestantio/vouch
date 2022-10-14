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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/attestantio/go-block-relay/services/blockauctioneer"
	builderclient "github.com/attestantio/go-builder-client"
	builderspec "github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

// zeroExecutionAddress is used for comparison purposes.
var zeroExecutionAddress bellatrix.ExecutionAddress

// zeroValue is used for comparison purposes.
var zeroValue uint256.Int

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
	if res == nil {
		return nil, nil
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

	// Update metrics.
	for provider, value := range res.Values {
		delta := new(big.Int).Sub(res.Bid.Data.Message.Value.ToBig(), value)
		if !strings.EqualFold(res.Provider.Address(), provider) {
			monitorBuilderBidDelta(provider, delta)
		}
		if s.logResults {
			log.Info().Uint64("slot", uint64(slot)).Str("provider", provider).Stringer("value", value).Stringer("delta", delta).Bool("selected", provider == res.Provider.Address()).Msg("Auction participant")
		} else {
			log.Trace().Uint64("slot", uint64(slot)).Str("provider", provider).Stringer("value", value).Stringer("delta", delta).Bool("selected", provider == res.Provider.Address()).Msg("Auction participant")
		}
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
	log := util.LogWithID(ctx, log, "strategy_id").With().Str("operation", "builderbid").Uint64("slot", uint64(slot)).Str("pubkey", fmt.Sprintf("%#x", pubkey)).Logger()

	s.executionConfigMu.RLock()
	proposerConfig, exists := s.executionConfig.ProposerConfigs[pubkey]
	if !exists {
		proposerConfig = s.executionConfig.DefaultConfig
	}
	s.executionConfigMu.RUnlock()

	if !proposerConfig.Builder.Enabled {
		log.Trace().Msg("Auction disabled in proposer configuration")
		return nil, nil
	}

	res := &blockauctioneer.Results{
		Values: make(map[string]*big.Int),
	}
	requests := len(proposerConfig.Builder.Relays)

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(ctx, s.timeout/2)

	respCh := make(chan *builderBidResponse, requests)
	errCh := make(chan error, requests)
	// Kick off the requests.
	for _, relay := range proposerConfig.Builder.Relays {
		builderClient, err := util.FetchBuilderClient(ctx, relay, s.monitor)
		if err != nil {
			// Error but continue.
			log.Error().Err(err).Msg("Failed to obtain builder client for block auction")
			continue
		}
		provider, isProvider := builderClient.(builderclient.BuilderBidProvider)
		if !isProvider {
			// Error but continue.
			log.Error().Err(err).Msg("Builder client does not supply builder bids")
			continue
		}
		go s.builderBid(ctx, provider, respCh, errCh, slot, parentHash, pubkey)
	}

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	timedOut := 0
	softTimedOut := 0
	bestScore := new(big.Int)

	// Loop 1: prior to soft timeout.
	for responded+errored+timedOut+softTimedOut != requests {
		select {
		case resp := <-respCh:
			responded++
			log.Trace().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Response received")
			if res.Bid == nil || resp.score.Cmp(bestScore) > 0 {
				res.Bid = resp.bid
				bestScore = resp.score
				res.Provider = resp.provider
			}
			res.Values[resp.provider.Address()] = resp.score
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
			if res.Bid == nil || resp.score.Cmp(bestScore) > 0 {
				res.Bid = resp.bid
				bestScore = resp.score
				res.Provider = resp.provider
			}
			res.Values[resp.provider.Address()] = resp.score
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
	log.Trace().Dur("elapsed", time.Since(started)).Int("responded", responded).Int("errored", errored).Int("timed_out", timedOut).Msg("Results")

	if res.Bid == nil {
		log.Debug().Msg("No bids received")
		monitorAuctionBlock("", false, time.Since(started))
		// No result, but not an error.
		return nil, nil
	}

	log.Trace().Stringer("bid", res.Bid).Msg("Selected best bid")
	monitorAuctionBlock(res.Provider.Address(), true, time.Since(started))

	return res, nil
}

func (s *Service) builderBid(ctx context.Context,
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
	if builderBid == nil {
		respCh <- &builderBidResponse{
			provider: provider,
			score:    big.NewInt(0),
		}
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
		if bytes.Equal(builderBid.Data.Message.Header.FeeRecipient[:], zeroExecutionAddress[:]) {
			errCh <- fmt.Errorf("%s: zero fee recipient", provider.Address())
			return
		}
		if zeroValue.Cmp(builderBid.Data.Message.Value) == 0 {
			errCh <- fmt.Errorf("%s: zero value", provider.Address())
			return
		}
		if uint64(s.chainTime.StartOfSlot(slot).Unix()) != builderBid.Data.Message.Header.Timestamp {
			errCh <- fmt.Errorf("%s: provided timestamp %d for slot %d not expected value of %d", provider.Address(), builderBid.Data.Message.Header.Timestamp, slot, s.chainTime.StartOfSlot(slot).Unix())
			return
		}
	default:
		errCh <- fmt.Errorf("%s: unhandled builder bid data version %v", provider.Address(), builderBid.Version)
	}

	respCh <- &builderBidResponse{
		bid:      builderBid,
		provider: provider,
		score:    builderBid.Data.Message.Value.ToBig(),
	}
}
