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
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// auctionResult provides information on the result of an auction process.
type auctionResult int

const (
	auctionResultSucceeded = iota + 1
	auctionResultFailed
	auctionResultFailedCanTryWithout
	auctionResultNoBids
)

// Propose proposes a block.
func (s *Service) Propose(ctx context.Context, data interface{}) {
	ctx, span := otel.Tracer("attestantio.vouch.services.beaconblockproposer.standard").Start(ctx, "Propose")
	defer span.End()
	started := time.Now()

	duty, ok := data.(*beaconblockproposer.Duty)
	if !ok {
		log.Error().Msg("Passed invalid data structure")
		s.monitor.BeaconBlockProposalCompleted(started, 0, "failed")
		return
	}
	if duty == nil {
		log.Error().Msg("Passed nil data structure")
		s.monitor.BeaconBlockProposalCompleted(started, 0, "failed")
		return
	}
	span.SetAttributes(attribute.Int64("slot", int64(duty.Slot())))
	log := log.With().Uint64("proposing_slot", uint64(duty.Slot())).Uint64("validator_index", uint64(duty.ValidatorIndex())).Logger()
	log.Trace().Msg("Proposing")

	var zeroSig phase0.BLSSignature
	if duty.RANDAOReveal() == zeroSig {
		log.Error().Msg("Missing RANDAO reveal")
		s.monitor.BeaconBlockProposalCompleted(started, duty.Slot(), "failed")
		return
	}

	if duty.Account() == nil {
		log.Error().Msg("Missing account")
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
	ctx, span := otel.Tracer("attestantio.vouch.services.beaconblockproposer.standard").Start(ctx, "proposeBlock")
	defer span.End()

	if s.blockAuctioneer != nil {
		// There is a block auctioneer specified, try to propose the block with auction.
		result := s.proposeBlockWithAuction(ctx, started, duty, graffiti)
		switch result {
		case auctionResultSucceeded:
			s.monitor.BeaconBlockProposalSource("auction")
			return nil
		case auctionResultFailedCanTryWithout:
			log.Warn().Msg("Failed to propose with auction; attempting to propose without auction")
		case auctionResultNoBids:
			log.Debug().Msg("No auction bids; attempting to propose without auction")
		case auctionResultFailed:
			return errors.New("failed to propose with auction too late in process, cannot fall back")
		}
	}

	err := s.proposeBlockWithoutAuction(ctx, started, duty, graffiti)
	if err != nil {
		return err
	}

	s.monitor.BeaconBlockProposalSource("direct")
	return nil
}

// proposeBlockWithAuction proposes a block after going through an auction for the blockspace.
func (s *Service) proposeBlockWithAuction(ctx context.Context,
	started time.Time,
	duty *beaconblockproposer.Duty,
	graffiti []byte,
) auctionResult {
	ctx, span := otel.Tracer("attestantio.vouch.services.beaconblockproposer.standard").Start(ctx, "proposeBlockWithAuction")
	defer span.End()

	log := log.With().Uint64("slot", uint64(duty.Slot())).Logger()

	pubkey := phase0.BLSPubKey{}
	if provider, isProvider := duty.Account().(e2wtypes.AccountCompositePublicKeyProvider); isProvider {
		copy(pubkey[:], provider.CompositePublicKey().Marshal())
	} else {
		copy(pubkey[:], duty.Account().PublicKey().Marshal())
	}
	hash, height := s.executionChainHeadProvider.ExecutionChainHead(ctx)
	log.Trace().Str("hash", fmt.Sprintf("%#x", hash)).Uint64("height", height).Msg("Current execution chain state")
	auctionResults, err := s.blockAuctioneer.AuctionBlock(ctx,
		duty.Slot(),
		hash,
		pubkey)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to auction block")
		return auctionResultFailedCanTryWithout
	}
	if auctionResults == nil || len(auctionResults.Values) == 0 {
		return auctionResultNoBids
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(auctionResults.Bid)
		if err == nil {
			e.RawJSON("header", data).Msg("Obtained best bid; using as header for beacon block proposals")
		}
	}

	proposal, err := s.blindedProposalProvider.BlindedBeaconBlockProposal(ctx, duty.Slot(), duty.RANDAOReveal(), graffiti)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain blinded proposal data")
		return auctionResultFailedCanTryWithout
	}
	if proposal == nil {
		log.Warn().Msg("Obtained nil blinded beacon block proposal")
		return auctionResultFailedCanTryWithout
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained blinded proposal")

	proposalSlot, err := proposal.Slot()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain proposal slot")
		return auctionResultFailedCanTryWithout
	}
	if proposalSlot != duty.Slot() {
		log.Warn().Msg("Proposal slot mismatch")
		return auctionResultFailedCanTryWithout
	}

	bodyRoot, err := proposal.BodyRoot()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain proposal body root")
		return auctionResultFailedCanTryWithout
	}

	parentRoot, err := proposal.ParentRoot()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain proposal parent root")
		return auctionResultFailedCanTryWithout
	}

	stateRoot, err := proposal.StateRoot()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain proposal state root")
		return auctionResultFailedCanTryWithout
	}

	proposalTransactionsRoot, err := proposal.TransactionsRoot()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain proposal transactions root")
		return auctionResultFailedCanTryWithout
	}
	auctionTransactionsRoot, err := auctionResults.Bid.TransactionsRoot()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain auction transactions root")
		return auctionResultFailedCanTryWithout
	}
	if !bytes.Equal(proposalTransactionsRoot[:], auctionTransactionsRoot[:]) {
		log.Debug().Str("proposal_transactions_root", fmt.Sprintf("%#x", proposalTransactionsRoot[:])).Str("auction_transactions_root", fmt.Sprintf("%#x", auctionTransactionsRoot[:])).Msg("Transactions root mismatch")
		// This is a mismatch, back out.
		return auctionResultFailedCanTryWithout
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(proposal)
		if err == nil {
			e.RawJSON("proposal", data).Msg("Obtained blinded proposal")
		}
	}

	// Ensure that the auction winner can (attempt to) unblind the block before we sign it.
	unblindedBlockProvider, isProvider := auctionResults.Provider.(builderclient.UnblindedBlockProvider)
	if !isProvider {
		log.Error().Msg("Auctioneer cannot unblind the block")
		return auctionResultFailedCanTryWithout
	}

	// As we cannot fall back we move to a retry system.
	retryInterval := 500 * time.Millisecond

	var signedBlock *spec.VersionedSignedBeaconBlock
	var sig *phase0.BLSSignature
	for retries := 3; retries > 0; retries-- {
		if sig == nil {
			blockSig, err := s.beaconBlockSigner.SignBeaconBlockProposal(ctx,
				duty.Account(),
				proposalSlot,
				duty.ValidatorIndex(),
				parentRoot,
				stateRoot,
				bodyRoot)
			if err != nil {
				log.Debug().Err(err).Int("retries", retries).Msg("Failed to sign blinded beacon block proposal")
				time.Sleep(retryInterval)
				continue
			}
			sig = &blockSig
			log.Trace().Dur("elapsed", time.Since(started)).Msg("Signed blinded proposal")
		}

		signedBlindedBlock := &api.VersionedSignedBlindedBeaconBlock{
			Version: proposal.Version,
		}
		switch signedBlindedBlock.Version {
		case spec.DataVersionBellatrix:
			signedBlindedBlock.Bellatrix = &apiv1.SignedBlindedBeaconBlock{
				Message:   proposal.Bellatrix,
				Signature: *sig,
			}
		default:
			log.Error().Int("version", int(signedBlock.Version)).Msg("Unknown proposal version")
			return auctionResultFailed
		}

		// Unblind the blinded block.
		ctx, span := otel.Tracer("attestantio.vouch.services.beaconblockproposer.standard").Start(ctx, "UnblindBlock", trace.WithAttributes(
			attribute.String("relay", unblindedBlockProvider.Address()),
		))
		signedBlock, err = unblindedBlockProvider.UnblindBlock(ctx, signedBlindedBlock)
		span.End()
		if err != nil {
			log.Debug().Err(err).Int("retries", retries).Msg("Failed to unblind block")
			time.Sleep(retryInterval)
			continue
		}
		break
	}
	if signedBlock == nil {
		log.Error().Msg("No signed block received")
		return auctionResultFailed
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(signedBlock)
		if err == nil {
			log.Trace().RawJSON("signed_block", data).Msg("Recomposed block to submit")
		}
	}

	// Submit the block.
	if err := s.beaconBlockSubmitter.SubmitBeaconBlock(ctx, signedBlock); err != nil {
		log.Error().Err(err).Msg("Failed to submit beacon block proposal")
		return auctionResultFailed
	}

	return auctionResultSucceeded
}

func (s *Service) proposeBlockWithoutAuction(ctx context.Context,
	started time.Time,
	duty *beaconblockproposer.Duty,
	graffiti []byte,
) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.beaconblockproposer.standard").Start(ctx, "proposeBlockWithoutAuction")
	defer span.End()

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
