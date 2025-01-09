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
	builderapi "github.com/attestantio/go-builder-client/api"
	builderspec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/blockrelay"
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
	builderConfigs map[phase0.BLSPubKey]*blockrelay.BuilderConfig,
) (
	*blockauctioneer.Results,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.builderbid.best").Start(ctx, "BuilderBid")
	defer span.End()
	started := time.Now()
	log := util.LogWithID(ctx, s.log, "strategy_id").With().
		Str("operation", "builderbid").
		Uint64("slot", uint64(slot)).
		Stringer("pubkey", pubkey).
		Logger()
	ctx = log.WithContext(ctx)

	res := &blockauctioneer.Results{
		AllProviders:  make([]builderclient.BuilderBidProvider, 0),
		Providers:     make([]builderclient.BuilderBidProvider, 0),
		Participation: make(map[string]*blockauctioneer.Participation),
	}
	requests := len(proposerConfig.Relays)

	// We have two timeouts: a soft timeout and a hard timeout.
	// At the soft timeout, we return if we have any responses so far.
	// At the hard timeout, we return unconditionally.
	// The soft timeout is half the duration of the hard timeout.
	hardCtx, cancel := context.WithTimeout(ctx, s.timeout)
	softCtx, softCancel := context.WithTimeout(hardCtx, s.timeout/2)

	respCh, errCh := s.issueBuilderBidRequests(ctx, slot, parentHash, pubkey, proposerConfig, res)
	span.AddEvent("Issued requests")

	responded, errored := s.builderBidLoop1(softCtx, started, requests, res, respCh, errCh, builderConfigs)
	softCancel()

	s.builderBidLoop2(hardCtx, started, requests, res, respCh, errCh, responded, errored, builderConfigs)
	cancel()

	for _, provider := range res.Providers {
		monitorAuctionBlock(provider.Address(), res.WinningParticipation.Category, true, time.Since(started))
	}

	return res, nil
}

func (s *Service) builderBidLoop1(ctx context.Context,
	started time.Time,
	requests int,
	res *blockauctioneer.Results,
	respCh chan *builderBidResponse,
	errCh chan *builderBidError,
	builderConfigs map[phase0.BLSPubKey]*blockrelay.BuilderConfig,
) (
	int,
	int,
) {
	log := zerolog.Ctx(ctx)

	// Wait for all responses (or context done).
	responded := 0
	errored := 0

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

			s.setBuilderBid(ctx, res, resp, builderConfigs)
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
			return responded, errored
		}
	}

	return responded, errored
}

func (s *Service) builderBidLoop2(ctx context.Context,
	started time.Time,
	requests int,
	res *blockauctioneer.Results,
	respCh chan *builderBidResponse,
	errCh chan *builderBidError,
	responded int,
	errored int,
	builderConfigs map[phase0.BLSPubKey]*blockrelay.BuilderConfig,
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

			s.setBuilderBid(ctx, res, resp, builderConfigs)
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
	builderConfigs map[phase0.BLSPubKey]*blockrelay.BuilderConfig,
) {
	log := zerolog.Ctx(ctx)

	// Obtain the builder config.
	builder, err := resp.bid.Builder()
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain builder from bid, response is invalid")
		return
	}
	builderConfig, exists := builderConfigs[builder]
	if !exists {
		// Generate a blank builder config.
		builderConfig = &blockrelay.BuilderConfig{
			Category: blockrelay.StandardBuilderCategory,
		}
	}

	// Calculate the bid score, with modifiers.
	score := resp.score
	if builderConfig.Offset != nil {
		score = new(big.Int).Add(score, builderConfig.Offset)
	}
	if builderConfig.Factor != nil {
		score = new(big.Int).Div(new(big.Int).Mul(score, builderConfig.Factor), big.NewInt(100))
	}

	participation := &blockauctioneer.Participation{
		Score:    score,
		Category: builderConfig.Category,
		Bid:      resp.bid,
	}

	// Set the winning participation.
	if score.Cmp(big.NewInt(0)) == 0 {
		log.Debug().Str("provider", resp.provider.Address()).Msg("Zero-score bid")
	} else {
		switch {
		case res.WinningParticipation == nil || score.Cmp(res.WinningParticipation.Score) > 0:
			log.Trace().Str("provider", resp.provider.Address()).Stringer("score", score).Msg("New high score")
			res.WinningParticipation = participation
			res.Providers = []builderclient.BuilderBidProvider{resp.provider}
		case res.WinningParticipation != nil && bidsEqual(participation.Bid, res.WinningParticipation.Bid):
			log.Trace().Str("provider", resp.provider.Address()).Msg("Additional provider with bid")
			res.Providers = append(res.Providers, resp.provider)
		default:
			log.Trace().Str("provider", resp.provider.Address()).Stringer("score", resp.score).Msg("Low or slow bid")
		}
	}

	// Set the provider participation.
	res.Participation[resp.provider.Address()] = participation
}

// issueBuilderBidRequests issues the builder bid requests to all suitable providers.
func (s *Service) issueBuilderBidRequests(ctx context.Context,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
	proposerConfig *beaconblockproposer.ProposerConfig,
	res *blockauctioneer.Results,
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
		go s.builderBid(ctx, provider, respCh, errCh, slot, parentHash, pubkey, relay)
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

	value, err := s.getBidValue(ctx, builderBid)
	if err != nil {
		errCh <- &builderBidError{
			provider: provider,
			err:      err,
		}

		return
	}

	if value.ToBig().Cmp(relayConfig.MinValue.BigInt()) < 0 {
		log.Debug().
			Stringer("value", value.ToBig()).
			Stringer("min_value", relayConfig.MinValue.BigInt()).
			Msg("Bid value below minimum; ignoring")
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

	resp, err := provider.BuilderBid(ctx, &builderapi.BuilderBidOpts{
		Slot:       slot,
		ParentHash: parentHash,
		PubKey:     pubkey,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain builder bid")
	}
	builderBid := resp.Data
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
	slotTimestamp := s.chainTime.StartOfSlot(slot)
	if util.Int64ToUint64(slotTimestamp.Unix()) != timestamp {
		return fmt.Errorf("provided timestamp %d for slot %d not expected value of %d", timestamp, slot, slotTimestamp.Unix())
	}

	s.verifyBidBlockGasLimit(ctx, bid, relayConfig)

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

func (s *Service) verifyBidBlockGasLimit(ctx context.Context,
	bid *builderspec.VersionedSignedBuilderBid,
	relayConfig *beaconblockproposer.RelayConfig,
) {
	log := zerolog.Ctx(ctx)

	bidHeight, err := bid.BlockNumber()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain builder bid height")

		return
	}

	bidGasLimit, err := bid.BlockGasLimit()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain builder bid block gas limit")

		return
	}

	previousGasLimit, exists := s.blockGasLimitProvider.BlockGasLimit(ctx, bidHeight-1)
	if !exists {
		log.Debug().Msg("Cannot obtain gas limit for prior block; skipping check")

		return
	}

	expectedGasLimit := util.ExpectedGasLimit(previousGasLimit, relayConfig.GasLimit)

	// See if the bid block gas limit is accurate.
	if bidGasLimit != expectedGasLimit {
		log.Warn().Uint64("expected_gas_limit", expectedGasLimit).Uint64("bid_gas_limit", bidGasLimit).Msg("Incorrect block gas limit")

		return
	}
	log.Trace().Uint64("bid_gas_limit", bidGasLimit).Msg("Correct block gas limit")
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
