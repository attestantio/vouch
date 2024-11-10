// Copyright © 2024 Attestant Limited.
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

package deadline

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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// zeroExecutionAddress is used for comparison purposes.
var zeroExecutionAddress bellatrix.ExecutionAddress

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
	ctx, span := otel.Tracer("attestantio.vouch.strategies.builderbid.deadline").Start(ctx, "BuilderBid")
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

	// We repeatedly query the relays until the deadline passes.
	deadline := s.chainTime.StartOfSlot(slot).Add(s.deadline)
	ctx, cancel := context.WithDeadline(ctx, deadline)

	respCh := make(chan *builderBidResponse, requests)
	errCh := make(chan *builderBidError, requests)
	// Kick off the requests.

	for _, relay := range proposerConfig.Relays {
		builderClient, err := util.FetchBuilderClient(ctx, relay.Address, s.monitor, s.releaseVersion)
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
		res.AllProviders = append(res.AllProviders, provider)
		go s.builderBid(ctx, provider, respCh, errCh, slot, parentHash, pubkey, relay, deadline)
	}

	// Wait for context done.
	providerResponses := make(map[string]int)
	providerErrors := make(map[string]int)

	done := false
	for !done {
		select {
		case resp := <-respCh:
			providerResponses[resp.provider.Address()]++
			log.Trace().Dur("elapsed", time.Since(started)).Str("provider", resp.provider.Address()).Msg("Response received")
			if resp.bid == nil {
				// This means that the bid was ineligible, for example the bid value was too small.
				continue
			}
			s.setBuilderBid(ctx, res, resp, builderConfigs)
		case err := <-errCh:
			providerErrors[err.provider.Address()]++
			log.Debug().Dur("elapsed", time.Since(started)).Str("provider", err.provider.Address()).Err(err.err).Msg("Error received")
		case <-ctx.Done():
			log.Trace().Dur("elapsed", time.Since(started)).Msg("Deadline reached")
			done = true
		}
	}

	cancel()

	for _, provider := range res.Providers {
		monitorAuctionBlock(provider.Address(), res.WinningParticipation.Category, true, time.Since(started))
	}

	return res, nil
}

func (s *Service) builderBid(ctx context.Context,
	provider builderclient.BuilderBidProvider,
	respCh chan *builderBidResponse,
	errCh chan *builderBidError,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
	relayConfig *beaconblockproposer.RelayConfig,
	deadline time.Time,
) {
	ctx, span := otel.Tracer("attestantio.vouch.strategies.builderbid.deadline").Start(ctx, "builderBid", trace.WithAttributes(
		attribute.String("relay", provider.Address()),
	))
	defer span.End()

	if relayConfig.Grace > 0 {
		time.Sleep(relayConfig.Grace)
		span.AddEvent("Grace period over")
	}

	var firstBid *builderspec.VersionedSignedBuilderBid
	var lastBid *builderspec.VersionedSignedBuilderBid
	bids := 0

	log := s.log.With().Str("relay", provider.Address()).Logger()
	for ; ; time.Sleep(s.bidGap) {
		firstBid, lastBid, bids = s.builderBidAttempt(ctx, &log, span, provider, respCh, errCh, slot, parentHash, pubkey, relayConfig, firstBid, lastBid, bids)

		if time.Until(deadline) <= s.bidGap {
			log.Trace().Int64("remaining_ms", time.Until(deadline).Milliseconds()).Msg("Not enough time to re-request bid")
			s.logBidResults(span, slot, provider.Address(), firstBid, lastBid, bids)

			return
		}
	}
}

func (s *Service) builderBidAttempt(ctx context.Context,
	log *zerolog.Logger,
	span trace.Span,
	provider builderclient.BuilderBidProvider,
	respCh chan *builderBidResponse,
	errCh chan *builderBidError,
	slot phase0.Slot,
	parentHash phase0.Hash32,
	pubkey phase0.BLSPubKey,
	relayConfig *beaconblockproposer.RelayConfig,
	firstBid *builderspec.VersionedSignedBuilderBid,
	lastBid *builderspec.VersionedSignedBuilderBid,
	bids int,
) (
	*builderspec.VersionedSignedBuilderBid,
	*builderspec.VersionedSignedBuilderBid,
	int,
) {
	resp, err := provider.BuilderBid(ctx, &builderapi.BuilderBidOpts{
		Slot:       slot,
		ParentHash: parentHash,
		PubKey:     pubkey,
	})
	if err != nil {
		if ctx.Err() == nil {
			// Error not on the context, report it.
			errCh <- &builderBidError{
				provider: provider,
				err:      err,
			}
		}
		s.logBidResults(span, slot, provider.Address(), firstBid, lastBid, bids)

		return firstBid, lastBid, bids
	}
	builderBid := resp.Data
	if builderBid == nil {
		respCh <- &builderBidResponse{
			provider: provider,
			score:    big.NewInt(0),
		}
		return firstBid, lastBid, bids
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(builderBid)
		if err == nil {
			e.Uint64("slot", uint64(slot)).RawJSON("builder_bid", data).Msg("Obtained builder bid")
		}
	}
	if builderBid.IsEmpty() {
		return firstBid, lastBid, bids
	}

	value, err := s.getBidValue(ctx, builderBid)
	if err != nil {
		errCh <- &builderBidError{
			provider: provider,
			err:      err,
		}

		return firstBid, lastBid, bids
	}

	if value.ToBig().Cmp(relayConfig.MinValue.BigInt()) < 0 {
		log.Trace().
			Uint64("slot", uint64(slot)).
			Stringer("value", value.ToBig()).
			Stringer("min_value", relayConfig.MinValue.BigInt()).
			Msg("Value below minimum; ignoring")

		return firstBid, lastBid, bids
	}

	if err := s.verifyBidDetails(ctx, builderBid, slot, relayConfig, provider); err != nil {
		errCh <- &builderBidError{
			provider: provider,
			err:      err,
		}

		return firstBid, lastBid, bids
	}

	bids++

	if firstBid == nil {
		firstBid = builderBid
	}

	if lastBid == nil || bidBetter(lastBid, builderBid) {
		lastBid = builderBid
		respCh <- &builderBidResponse{
			bid:      builderBid,
			provider: provider,
			score:    value.ToBig(),
		}
	}

	return firstBid, lastBid, bids
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

func (s *Service) logBidResults(span trace.Span,
	slot phase0.Slot,
	provider string,
	firstBid *builderspec.VersionedSignedBuilderBid,
	lastBid *builderspec.VersionedSignedBuilderBid,
	bids int,
) {
	if firstBid == nil || lastBid == nil {
		return
	}

	span.SetAttributes(attribute.Int("bids", bids))

	firstValue, err := firstBid.Value()
	if err != nil {
		s.log.Warn().Err(err).Msg("Failed to obtain first bid value for reporting")
		return
	}

	lastValue, err := lastBid.Value()
	if err != nil {
		s.log.Warn().Err(err).Msg("Failed to obtain last bid value for reporting")
		return
	}

	delta := new(uint256.Int).Sub(lastValue, firstValue).ToBig()
	pctDelta := float64(new(big.Int).Div(new(big.Int).Mul(delta, big.NewInt(10000)), firstValue.ToBig()).Int64()) / 100.00
	if pctDelta == 0.00 {
		span.SetAttributes(attribute.String("value", firstValue.Dec()))
	} else {
		span.SetAttributes(attribute.String("first_value", firstValue.Dec()),
			attribute.String("last_value", lastValue.Dec()),
			attribute.Float64("pct_delta", pctDelta),
		)
		monitorBidDelta(provider, delta, pctDelta)
	}
	s.log.Trace().Uint64("slot", uint64(slot)).Str("provider", provider).Int("bids", bids).Str("first_value", firstValue.PrettyDec(',')).Str("last_value", lastValue.PrettyDec(',')).Float64("pct_increase", pctDelta).Msg("Bid range")
}

// verifyBidSignature verifies the signature of a bid to ensure it comes from the expected source.
func (s *Service) verifyBidSignature(_ context.Context,
	relayConfig *beaconblockproposer.RelayConfig,
	bid *builderspec.VersionedSignedBuilderBid,
	provider builderclient.BuilderBidProvider,
) (
	bool,
	error,
) {
	var err error
	log := s.log.With().Str("provider", provider.Address()).Logger()

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

	return value, nil
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

// bidBetter returns true if the second bid has a higher value than the first.
func bidBetter(bid1 *builderspec.VersionedSignedBuilderBid, bid2 *builderspec.VersionedSignedBuilderBid) bool {
	value1, err := bid1.Value()
	if err != nil {
		return false
	}
	value2, err := bid2.Value()
	if err != nil {
		return false
	}

	return new(uint256.Int).Sub(value2, value1).Sign() == 1
}
