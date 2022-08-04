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

package standard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	builderclient "github.com/attestantio/go-builder-client"
	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Propose proposes a block.
func (s *Service) Propose(ctx context.Context, data interface{}) {
	started := time.Now()

	duty, ok := data.(*beaconblockproposer.Duty)
	if !ok {
		log.Error().Msg("Passed invalid data structure")
		s.monitor.BeaconBlockProposalCompleted(started, 0, "failed")
		return
	}
	log := log.With().Uint64("proposing_slot", uint64(duty.Slot())).Uint64("validator_index", uint64(duty.ValidatorIndex())).Logger()
	log.Trace().Msg("Proposing")

	var zeroSig phase0.BLSSignature
	if duty.RANDAOReveal() == zeroSig {
		log.Error().Msg("Missing RANDAO reveal")
		s.monitor.BeaconBlockProposalCompleted(started, duty.Slot(), "failed")
		return
	}

	var graffiti []byte
	var err error
	if s.graffitiProvider != nil {
		graffiti, err = s.graffitiProvider.Graffiti(ctx, duty.Slot(), duty.ValidatorIndex())
		if err != nil {
			log.Warn().Err(err).Msg("Failed to obtain graffiti")
			graffiti = nil
		}
	}
	if bytes.Contains(graffiti, []byte("{{CLIENT}}")) {
		if nodeClientProvider, isProvider := s.proposalProvider.(consensusclient.NodeClientProvider); isProvider {
			nodeClient, err := nodeClientProvider.NodeClient(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to obtain node client; not updating graffiti")
			} else {
				graffiti = bytes.ReplaceAll(graffiti, []byte("{{CLIENT}}"), []byte(nodeClient))
			}
		}
	}
	if len(graffiti) > 32 {
		graffiti = graffiti[0:32]
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained graffiti")

	if err := s.proposeBlock(ctx, started, duty, graffiti); err != nil {
		log.Error().Err(err).Msg("Failed to propose block")
		s.monitor.BeaconBlockProposalCompleted(started, duty.Slot(), "failed")
		return
	}

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted proposal")
	s.monitor.BeaconBlockProposalCompleted(started, duty.Slot(), "succeeded")
}

// proposeBlock proposes a beacon block.
func (s *Service) proposeBlock(ctx context.Context,
	started time.Time,
	duty *beaconblockproposer.Duty,
	graffiti []byte,
) error {
	if s.blockAuctioneer != nil {
		// There is a block auctioneer specified, try to propose the block with auction.
		canTryWithout, err := s.proposeBlockWithAuction(ctx, started, duty, graffiti)
		if err == nil {
			return nil
		}
		if canTryWithout {
			log.Warn().Err(err).Msg("Failed to propose with auction; attempting to propose without it")
		} else {
			return errors.Wrap(err, "failed to propose with auction, already signed so cannot fall back")
		}
	}
	return s.proposeBlockWithoutAuction(ctx, started, duty, graffiti)
}

// proposeBlock proposes a block after going through an auction for the blockspace.
func (s *Service) proposeBlockWithAuction(ctx context.Context,
	started time.Time,
	duty *beaconblockproposer.Duty,
	graffiti []byte,
) (
	bool, // True if it is okay to propose without auction.
	error,
) {
	// We start off being able to fall back to using the non-auction method if we fail.
	canTryWithout := true

	pubkey := phase0.BLSPubKey{}
	if provider, isProvider := duty.Account().(e2wtypes.AccountCompositePublicKeyProvider); isProvider {
		copy(pubkey[:], provider.CompositePublicKey().Marshal())
	} else {
		copy(pubkey[:], duty.Account().PublicKey().Marshal())
	}
	hash, height := s.executionChainHeadProvider.ExecutionChainHead(ctx)
	log.Info().Str("hash", fmt.Sprintf("%#x", hash)).Uint64("height", height).Uint64("slot", uint64(duty.Slot())).Msg("Current execution chain state")
	auctionResults, err := s.blockAuctioneer.AuctionBlock(ctx,
		duty.Slot(),
		hash,
		pubkey)
	if err != nil {
		return canTryWithout, errors.Wrap(err, "failed to auction block")
	}
	if auctionResults == nil {
		return canTryWithout, errors.New("auction returned no results")
	}
	if len(auctionResults.Values) == 0 {
		return canTryWithout, errors.New("no bids obtained for block")
	}
	// TODO more checks on the auction results?
	for provider, value := range auctionResults.Values {
		log.Trace().Str("provider", provider).Stringer("value", value).Msg("Bid")
	}
	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(auctionResults.Bid)
		if err == nil {
			e.RawJSON("header", data).Msg("Obtained bid")
		}
	}

	proposal, err := s.blindedProposalProvider.BlindedBeaconBlockProposal(ctx, duty.Slot(), duty.RANDAOReveal(), graffiti)
	if err != nil {
		return canTryWithout, errors.Wrap(err, "failed to obtain blinded proposal data")
	}
	if proposal == nil {
		return canTryWithout, errors.New("obtained nil blinded beacon block proposal")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained blinded proposal")

	proposalSlot, err := proposal.Slot()
	if err != nil {
		return canTryWithout, errors.Wrap(err, "failed to obtain proposal slot")
	}

	if proposalSlot != duty.Slot() {
		return canTryWithout, errors.New("proposal data for incorrect slot")
	}

	bodyRoot, err := proposal.BodyRoot()
	if err != nil {
		return canTryWithout, errors.Wrap(err, "failed to calculate hash tree root of block body")
	}

	parentRoot, err := proposal.ParentRoot()
	if err != nil {
		return canTryWithout, errors.Wrap(err, "failed to obtain parent root of block")
	}

	stateRoot, err := proposal.StateRoot()
	if err != nil {
		return canTryWithout, errors.Wrap(err, "failed to obtain state root of block")
	}

	// TODO make secure against nil.
	log.Info().Str("proposal", fmt.Sprintf("%#x", proposal.Bellatrix.Body.ExecutionPayloadHeader.TransactionsRoot[:])).Str("auction", fmt.Sprintf("%#x", auctionResults.Bid.Data.Message.Header.TransactionsRoot[:])).Msg("Transaction roots")
	if !bytes.Equal(proposal.Bellatrix.Body.ExecutionPayloadHeader.TransactionsRoot[:], auctionResults.Bid.Data.Message.Header.TransactionsRoot[:]) {
		// This is a mismatch, back out.
		return canTryWithout, errors.New("transactions root mismatch")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(proposal)
		if err == nil {
			e.RawJSON("proposal", data).Msg("Obtained proposal")
		}
	}

	// Ensure that the auction winner can (attempt to) unblind the block before we sign it.
	unblindedBlockProvider, isProvider := auctionResults.Provider.(builderclient.UnblindedBlockProvider)
	if !isProvider {
		return canTryWithout, errors.New("auctioneer cannot unblind the block")
	}

	// If there are failures from this point forwards we cannot safely propose without the auction.
	canTryWithout = false

	sig, err := s.beaconBlockSigner.SignBeaconBlockProposal(ctx,
		duty.Account(),
		proposalSlot,
		duty.ValidatorIndex(),
		parentRoot,
		stateRoot,
		bodyRoot)
	if err != nil {
		return canTryWithout, errors.Wrap(err, "failed to sign blinded beacon block proposal")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Signed blinded proposal")

	signedBlindedBlock := &api.VersionedSignedBlindedBeaconBlock{
		Version: proposal.Version,
	}
	switch signedBlindedBlock.Version {
	case spec.DataVersionBellatrix:
		signedBlindedBlock.Bellatrix = &apiv1.SignedBlindedBeaconBlock{
			Message:   proposal.Bellatrix,
			Signature: sig,
		}
	default:
		return canTryWithout, fmt.Errorf("unknown proposal version %v", signedBlindedBlock.Version)
	}

	// Unblind the blinded block.
	signedBlock, err := unblindedBlockProvider.UnblindBlock(ctx, signedBlindedBlock)
	if err != nil {
		return canTryWithout, errors.Wrap(err, "failed to unblind block")
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(signedBlock)
		if err == nil {
			log.Trace().RawJSON("signed_block", data).Msg("Recomposed block to submit")
		}
	}

	// Submit the block.
	if err := s.beaconBlockSubmitter.SubmitBeaconBlock(ctx, signedBlock); err != nil {
		return canTryWithout, errors.Wrap(err, "failed to submit beacon block proposal")
	}

	return canTryWithout, nil
}

func (s *Service) proposeBlockWithoutAuction(ctx context.Context,
	started time.Time,
	duty *beaconblockproposer.Duty,
	graffiti []byte,
) error {
	proposal, err := s.proposalProvider.BeaconBlockProposal(ctx, duty.Slot(), duty.RANDAOReveal(), graffiti)
	if err != nil {
		return errors.Wrap(err, "failed to obtain proposal data")
	}
	if proposal == nil {
		return errors.New("obtained nil beacon block proposal")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained proposal")

	proposalSlot, err := proposal.Slot()
	if err != nil {
		return errors.Wrap(err, "failed to obtain proposal slot")
	}

	if proposalSlot != duty.Slot() {
		return errors.New("proposal data for incorrect slot")
	}

	bodyRoot, err := proposal.BodyRoot()
	if err != nil {
		return errors.Wrap(err, "failed to calculate hash tree root of block body")
	}

	parentRoot, err := proposal.ParentRoot()
	if err != nil {
		return errors.Wrap(err, "failed to obtain parent root of block")
	}

	stateRoot, err := proposal.StateRoot()
	if err != nil {
		return errors.Wrap(err, "failed to obtain state root of block")
	}

	sig, err := s.beaconBlockSigner.SignBeaconBlockProposal(ctx,
		duty.Account(),
		proposalSlot,
		duty.ValidatorIndex(),
		parentRoot,
		stateRoot,
		bodyRoot)
	if err != nil {
		return errors.Wrap(err, "failed to sign beacon block proposal")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Signed proposal")

	signedBlock := &spec.VersionedSignedBeaconBlock{
		Version: proposal.Version,
	}
	switch signedBlock.Version {
	case spec.DataVersionPhase0:
		signedBlock.Phase0 = &phase0.SignedBeaconBlock{
			Message:   proposal.Phase0,
			Signature: sig,
		}
	case spec.DataVersionAltair:
		signedBlock.Altair = &altair.SignedBeaconBlock{
			Message:   proposal.Altair,
			Signature: sig,
		}
	case spec.DataVersionBellatrix:
		signedBlock.Bellatrix = &bellatrix.SignedBeaconBlock{
			Message:   proposal.Bellatrix,
			Signature: sig,
		}
	default:
		return errors.New("unknown proposal version")
	}

	// Submit the block.
	if err := s.beaconBlockSubmitter.SubmitBeaconBlock(ctx, signedBlock); err != nil {
		return errors.Wrap(err, "failed to submit beacon block proposal")
	}

	return nil
}

// TODO remove this
// Fetch the beacon block proposal and the builder bid in parallel.
// TODO move to blockrelay.
// pubkey := duty.Account().PublicKey()
// if provider, isProvider := duty.Account().(e2wtypes.AccountCompositePublicKeyProvider); isProvider {
// 	pubkey = provider.CompositePublicKey()
// }
// pubKey := phase0.BLSPubKey{}
// copy(pubKey[:], pubkey.Marshal())
// hash, height := s.executionChainHeadProvider.ExecutionChainHead(ctx)
// log.Info().Str("hash", fmt.Sprintf("%#x", hash)).Uint64("height", height).Uint64("slot", uint64(duty.Slot())).Msg("Current execution chain state")
// builderBid, err := s.builderBidProviders[0].BuilderBid(ctx, duty.Slot(), hash, pubKey)
// if err != nil {
// 	return errors.Wrap(err, "failed to obtain builder bid")
// }
// if builderBid == nil {
// 	return errors.New("obtained nil builder bid")
// }
// log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained builder bid")

//	// TODO temp.
//	if true {
//		pubkey := duty.Account().PublicKey()
//		if provider, isProvider := duty.Account().(e2wtypes.AccountCompositePublicKeyProvider); isProvider {
//			pubkey = provider.CompositePublicKey()
//		}
//		pubKey := phase0.BLSPubKey{}
//		copy(pubKey[:], pubkey.Marshal())
//		hash, height := s.executionChainHeadProvider.ExecutionChainHead(ctx)
//		log.Info().Str("hash", fmt.Sprintf("%#x", hash)).Uint64("height", height).Uint64("slot", uint64(duty.Slot())).Msg("Current execution chain state")
//		go func() {
//			for name, builderBidProvider := range s.builderBidProviders {
//				builderBid, err := builderBidProvider.BuilderBid(ctx, duty.Slot(), hash, pubKey)
//				if err != nil {
//					log.Warn().Err(err).Msg("Failed to obtain builder bid")
//					return
//				}
//				data, err := json.Marshal(builderBid)
//				if err != nil {
//					log.Warn().Err(err).Msg("Failed to marshal builder bid")
//					return
//				}
//				log.Info().Str("builder", name).RawJSON("builder_bid", data).Msg("Obtained builder bid")
//			}
//		}()
//	}
