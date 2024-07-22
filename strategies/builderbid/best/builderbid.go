// Copyright © 2023, 2024 Attestant Limited.
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
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/attestantio/go-block-relay/services/blockauctioneer"
	builderclient "github.com/attestantio/go-builder-client"
	builderspec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/util"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	"go.opentelemetry.io/otel"
)

// zeroExecutionAddress is used for comparison purposes.
var zeroExecutionAddress bellatrix.ExecutionAddress

// zeroValue is used for comparison purposes.
var zeroValue uint256.Int

type builderBidResponse struct {
	provider builderclient.BuilderBidProvider
	bid      *builderspec.VersionedSignedBuilderBid
	score    *big.Int
}

type builderBidError struct {
	provider builderclient.BuilderBidProvider
	err      error
}

// BuilderBid provides the best builder bid from a number of relays.
func (s *Service) BuilderBid(ctx context.Context,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
	proposerConfig *beaconblockproposer.ProposerConfig,
	excludedBuilders []phase0.BLSPubKey,
	privilegedBuilders []phase0.BLSPubKey,
) (
	*blockauctioneer.Results,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.builderbid.best").Start(ctx, "BuilderBid")
	defer span.End()
	started := time.Now()
	log := util.LogWithID(ctx, s.log, "strategy_id").With().Str("operation", "builderbid").Uint64("slot", uint64(slot)).Str("pubkey", fmt.Sprintf("%#x", pubkey)).Logger()
	ctx = log.WithContext(ctx)

	res := &blockauctioneer.Results{
		AllProviders: make([]builderclient.BuilderBidProvider, 0),
		Values:       make(map[string]*big.Int),
		Providers:    make([]builderclient.BuilderBidProvider, 0),
	}
	resPrivileged := &blockauctioneer.Results{
		AllProviders: make([]builderclient.BuilderBidProvider, 0),
		Values:       make(map[string]*big.Int),
		Providers:    make([]builderclient.BuilderBidProvider, 0),
	}
	requests := len(proposerConfig.Relays)

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	hardCtx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(hardCtx, s.timeout/2)

	respCh, errCh := s.issueBuilderBidRequests(ctx, slot, parentHash, pubkey, proposerConfig, excludedBuilders, res, resPrivileged)
	span.AddEvent("Issued requests")

	responded, errored, bestScore, bestPrivilegedScore := s.builderBidLoop1(softCtx, started, requests, res, resPrivileged, respCh, errCh, privilegedBuilders)
	softCancel()

	s.builderBidLoop2(hardCtx, started, requests, res, resPrivileged, respCh, errCh, responded, errored, bestScore, bestPrivilegedScore, privilegedBuilders)
	cancel()

	if resPrivileged.Bid == nil && res.Bid == nil {
		log.Debug().Msg("No useful bids received")
		monitorAuctionBlock("", false, time.Since(started))
		return res, nil
	}

	if resPrivileged.Bid != nil {
		log.Trace().Stringer("bid", resPrivileged.Bid).Msg("Selected best privileged bid")

		for _, provider := range resPrivileged.Providers {
			monitorAuctionPrivilegedBlock(provider.Address(), true, time.Since(started))
		}

		return resPrivileged, nil
	}

	log.Trace().Stringer("bid", res.Bid).Msg("Selected best bid")

	for _, provider := range res.Providers {
		monitorAuctionBlock(provider.Address(), true, time.Since(started))
	}

	return res, nil
}

func (s *Service) builderBidLoop1(ctx context.Context,
	started time.Time,
	requests int,
	res *blockauctioneer.Results,
	resPrivileged *blockauctioneer.Results,
	respCh chan *builderBidResponse,
	errCh chan *builderBidError,
	privilegedBuilders []phase0.BLSPubKey,
) (
	int,
	int,
	*big.Int,
	*big.Int,
) {
	log := zerolog.Ctx(ctx)

	// Wait for all responses (or context done).
	responded := 0
	errored := 0
	bestScore := big.NewInt(0)
	bestPrivilegedScore := big.NewInt(0)

	for responded+errored != requests {
		select {
		case resp := <-respCh:
			responded++
			log.Trace().
				Dur("elapsed", time.Since(started)).
				Str("provider", resp.provider.Address()).
				Int("responded", responded).
				Int("errored", errored).
				Msg("Response received")
			if resp.bid == nil {
				// This means that the bid was ineligible, for example the bid value was too small.
				continue
			}

			builder, err := resp.bid.Builder()
			if err != nil {
				log.Error().Err(err).Msg("Failed to obtain builder from bid, response is invalid")
				continue
			}

			if isPrivilegedBuilder(builder, privilegedBuilders) {
				s.setBuilderBid(ctx, resPrivileged, resp, bestPrivilegedScore)
			} else {
				s.setBuilderBid(ctx, res, resp, bestScore)
			}
		case err := <-errCh:
			errored++
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Str("provider", err.provider.Address()).
				Int("responded", responded).
				Int("errored", errored).
				Err(err.err).
				Msg("Error received")
		case <-ctx.Done():
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", requests-responded-errored).
				Msg("Soft timeout reached")
			return responded, errored, bestScore, bestPrivilegedScore
		}
	}

	return responded, errored, bestScore, bestPrivilegedScore
}

func (s *Service) builderBidLoop2(ctx context.Context,
	started time.Time,
	requests int,
	res *blockauctioneer.Results,
	resPrivileged *blockauctioneer.Results,
	respCh chan *builderBidResponse,
	errCh chan *builderBidError,
	responded int,
	errored int,
	bestScore *big.Int,
	bestPrivilegedScore *big.Int,
	privilegedBuilders []phase0.BLSPubKey,
) {
	log := zerolog.Ctx(ctx)

	for responded+errored != requests {
		select {
		case resp := <-respCh:
			responded++
			log.Trace().
				Dur("elapsed", time.Since(started)).
				Str("provider", resp.provider.Address()).
				Int("responded", responded).
				Int("errored", errored).
				Msg("Response received")
			if resp.bid == nil {
				// This means that the bid was ineligible, for example the bid value was too small.
				continue
			}
			builder, err := resp.bid.Builder()
			if err != nil {
				log.Error().Err(err).Msg("Failed to obtain builder from bid, response is invalid")
				continue
			}

			if isPrivilegedBuilder(builder, privilegedBuilders) {
				s.setBuilderBid(ctx, resPrivileged, resp, bestPrivilegedScore)
			} else {
				s.setBuilderBid(ctx, res, resp, bestScore)
			}
		case err := <-errCh:
			errored++
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Str("provider", err.provider.Address()).
				Int("responded", responded).
				Int("errored", errored).
				Err(err.err).
				Msg("Error received")
		case <-ctx.Done():
			log.Debug().
				Dur("elapsed", time.Since(started)).
				Int("responded", responded).
				Int("errored", errored).
				Int("timed_out", requests-responded-errored).
				Msg("Hard timeout reached")
			return
		}
	}

	log.Trace().
		Dur("elapsed", time.Since(started)).
		Int("responded", responded).
		Int("errored", errored).
		Msg("Results")
}

func (*Service) setBuilderBid(ctx context.Context,
	res *blockauctioneer.Results,
	resp *builderBidResponse,
	bestScore *big.Int,
) {
	log := zerolog.Ctx(ctx)

	switch {
	case resp.score.Cmp(bestScore) > 0:
		res.Bid = resp.bid
		bestScore.Set(resp.score)
		res.Providers = make([]builderclient.BuilderBidProvider, 0)
		res.Providers = append(res.Providers, resp.provider)
		log.Trace().Str("provider", resp.provider.Address()).Stringer("score", bestScore).Msg("New winning bid")
	case res.Bid != nil && resp.score.Cmp(bestScore) == 0 && bidsEqual(res.Bid, resp.bid):
		log.Trace().Str("provider", resp.provider.Address()).Msg("Matching bid from different relay")
		res.Providers = append(res.Providers, resp.provider)
	default:
		log.Debug().Str("provider", resp.provider.Address()).Stringer("score", resp.score).Msg("Low or slow bid")
	}
	res.Values[resp.provider.Address()] = resp.score
}

// issueBuilderBidRequests issues the builder bid requests to all suitable providers.
func (s *Service) issueBuilderBidRequests(ctx context.Context,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
	proposerConfig *beaconblockproposer.ProposerConfig,
	excludedBuilders []phase0.BLSPubKey,
	res *blockauctioneer.Results,
	resPrivileged *blockauctioneer.Results,
) (
	chan *builderBidResponse,
	chan *builderBidError,
) {
	log := zerolog.Ctx(ctx)

	requests := len(proposerConfig.Relays)

	respCh := make(chan *builderBidResponse, requests)
	errCh := make(chan *builderBidError, requests)
	// Kick off the requests.  Continue on errors to issue as many requests as we are able.
	for _, relay := range proposerConfig.Relays {
		builderClient, err := util.FetchBuilderClient(ctx, relay.Address, s.monitor, s.releaseVersion)
		if err != nil {
			log.Error().Str("address", builderClient.Address()).Err(err).Msg("Failed to obtain builder client for block auction")
			continue
		}
		provider, isProvider := builderClient.(builderclient.BuilderBidProvider)
		if !isProvider {
			log.Error().Str("address", builderClient.Address()).Err(err).Msg("Builder client does not supply builder bids")
			continue
		}
		if _, isProvider := builderClient.(builderclient.UnblindedProposalProvider); !isProvider {
			log.Error().Str("address", builderClient.Address()).Msg("Builder client cannot unblind block; ignoring")
			continue
		}
		res.AllProviders = append(res.AllProviders, provider)
		resPrivileged.AllProviders = append(resPrivileged.AllProviders, provider)
		go s.builderBid(ctx, provider, respCh, errCh, slot, parentHash, pubkey, relay, excludedBuilders)
	}

	return respCh, errCh
}

func (s *Service) builderBid(ctx context.Context,
	provider builderclient.BuilderBidProvider,
	respCh chan *builderBidResponse,
	errCh chan *builderBidError,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
	relayConfig *beaconblockproposer.RelayConfig,
	excludedBuilders []phase0.BLSPubKey,
) {
	log := zerolog.Ctx(ctx).With().Str("relay", provider.Address()).Logger()

	if relayConfig.Grace > 0 {
		time.Sleep(relayConfig.Grace)
	}

	builderBid, err := s.obtainBid(ctx, provider, slot, parentHash, pubkey)
	if err != nil {
		errCh <- &builderBidError{
			provider: provider,
			err:      err,
		}

		return
	}
	if builderBid == nil {
		respCh <- &builderBidResponse{
			provider: provider,
			score:    big.NewInt(0),
		}

		return
	}

	if len(excludedBuilders) > 0 {
		builder, err := builderBid.Builder()
		if err != nil {
			errCh <- &builderBidError{
				provider: provider,
				err:      err,
			}

			return
		}
		for _, excludedBuilder := range excludedBuilders {
			if bytes.Equal(builder[:], excludedBuilder[:]) {
				log.Debug().Stringer("builder", builder).Msg("Bid by excluded builder; ignoring")
				respCh <- &builderBidResponse{
					provider: provider,
					score:    big.NewInt(0),
				}

				return
			}
		}
	}

	value, err := s.getBidValue(ctx, builderBid)
	if err != nil {
		errCh <- &builderBidError{
			provider: provider,
			err:      err,
		}

		return
	}

	if value.ToBig().Cmp(relayConfig.MinValue.BigInt()) < 0 {
		log.Debug().Stringer("value", value.ToBig()).Stringer("min_value", relayConfig.MinValue.BigInt()).Msg("Bid value below minimum; ignoring")
		respCh <- &builderBidResponse{
			provider: provider,
			score:    big.NewInt(0),
		}

		return
	}

	if err := s.verifyBidDetails(ctx, builderBid, slot, relayConfig, provider); err != nil {
		errCh <- &builderBidError{
			provider: provider,
			err:      err,
		}

		return
	}

	respCh <- &builderBidResponse{
		bid:      builderBid,
		provider: provider,
		score:    value.ToBig(),
	}
}

func (*Service) obtainBid(ctx context.Context,
	provider builderclient.BuilderBidProvider,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
) (
	*builderspec.VersionedSignedBuilderBid,
	error,
) {
	log := zerolog.Ctx(ctx).With().Str("bidder", provider.Address()).Logger()

	builderBid, err := provider.BuilderBid(ctx, slot, parentHash, pubkey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain builder bid")
	}
	if builderBid == nil {
		return nil, nil
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(builderBid)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal bid")
		}
		e.RawJSON("builder_bid", data).Msg("Obtained builder bid")
	}

	if builderBid.IsEmpty() {
		return nil, errors.New("builder bid empty")
	}

	return builderBid, nil
}

func (*Service) getBidValue(_ context.Context,
	bid *builderspec.VersionedSignedBuilderBid,
) (
	*uint256.Int,
	error,
) {
	value, err := bid.Value()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain bid value")
	}
	if zeroValue.Cmp(value) == 0 {
		return nil, errors.New("bid has 0 value")
	}

	return value, nil
}

func (s *Service) verifyBidDetails(ctx context.Context,
	bid *builderspec.VersionedSignedBuilderBid,
	slot phase0.Slot,
	relayConfig *beaconblockproposer.RelayConfig,
	provider builderclient.BuilderBidProvider,
) error {
	log := zerolog.Ctx(ctx)

	feeRecipient, err := bid.FeeRecipient()
	if err != nil {
		return errors.Wrap(err, "failed to obtain builder bid fee recipient")
	}
	if bytes.Equal(feeRecipient[:], zeroExecutionAddress[:]) {
		return errors.New("zero fee recipient")
	}

	timestamp, err := bid.Timestamp()
	if err != nil {
		return errors.Wrap(err, "failed to obtain builder bid timestamp")
	}
	if uint64(s.chainTime.StartOfSlot(slot).Unix()) != timestamp {
		return fmt.Errorf("provided timestamp %d for slot %d not expected value of %d", timestamp, slot, s.chainTime.StartOfSlot(slot).Unix())
	}

	verified, err := s.verifyBidSignature(ctx, relayConfig, bid, provider)
	if err != nil {
		return err
	}
	if !verified {
		log.Warn().Msg("Failed to verify bid signature")
		return errors.New("invalid signature")
	}

	return nil
}

// verifyBidSignature verifies the signature of a bid to ensure it comes from the expected source.
func (s *Service) verifyBidSignature(ctx context.Context,
	relayConfig *beaconblockproposer.RelayConfig,
	bid *builderspec.VersionedSignedBuilderBid,
	provider builderclient.BuilderBidProvider,
) (
	bool,
	error,
) {
	log := zerolog.Ctx(ctx).With().Str("provider", provider.Address()).Logger()

	relayPubkey := relayConfig.PublicKey
	if relayPubkey == nil {
		// Try to fetch directly from the provider.
		relayPubkey = provider.Pubkey()
		if relayPubkey == nil {
			log.Trace().Msg("Relay configuration does not contain public key; skipping validation")
			return true, nil
		}
	}

	s.relayPubkeysMu.RLock()
	pubkey, exists := s.relayPubkeys[*relayPubkey]
	s.relayPubkeysMu.RUnlock()
	if !exists {
		var err error
		pubkey, err = e2types.BLSPublicKeyFromBytes(relayPubkey[:])
		if err != nil {
			return false, errors.Wrap(err, "invalid public key supplied with bid")
		}
		s.relayPubkeysMu.Lock()
		s.relayPubkeys[*relayPubkey] = pubkey
		s.relayPubkeysMu.Unlock()
	}

	dataRoot, err := bid.MessageHashTreeRoot()
	if err != nil {
		return false, errors.Wrap(err, "failed to hash bid message")
	}

	signingData := &phase0.SigningData{
		ObjectRoot: dataRoot,
		Domain:     s.applicationBuilderDomain,
	}
	signingRoot, err := signingData.HashTreeRoot()
	if err != nil {
		return false, errors.Wrap(err, "failed to hash signing data")
	}

	bidSig, err := bid.Signature()
	if err != nil {
		return false, errors.Wrap(err, "failed to obtain bid signature")
	}

	byteSig := make([]byte, len(bidSig))
	copy(byteSig, bidSig[:])
	sig, err := e2types.BLSSignatureFromBytes(byteSig)
	if err != nil {
		return false, errors.Wrap(err, "invalid signature")
	}

	verified := sig.Verify(signingRoot[:], pubkey)
	if !verified {
		data, err := json.Marshal(bid)
		if err == nil {
			log.Debug().RawJSON("bid", data).Msg("Verification failure")
		}
	}

	return verified, nil
}

// bidsEqual returns true if the two bids are equal.
// Bids are considered equal if they have the same header.
// Note that this function is only called if the bids have the same value, so that is not checked here.
func bidsEqual(bid1 *builderspec.VersionedSignedBuilderBid, bid2 *builderspec.VersionedSignedBuilderBid) bool {
	bid1Root, err := bid1.HeaderHashTreeRoot()
	if err != nil {
		return false
	}
	bid2Root, err := bid2.HeaderHashTreeRoot()
	if err != nil {
		return false
	}
	return bytes.Equal(bid1Root[:], bid2Root[:])
}

func isPrivilegedBuilder(pubkey phase0.BLSPubKey, privilegedBuilders []phase0.BLSPubKey) bool {
	for _, builder := range privilegedBuilders {
		if bytes.Equal(pubkey[:], builder[:]) {
			return true
		}
	}
	return false
}
