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

	"github.com/attestantio/go-block-relay/services/blockauctioneer"
	builderclient "github.com/attestantio/go-builder-client"
	builderspec "github.com/attestantio/go-builder-client/spec"
	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	apiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/semaphore"
)

type BlindedBeaconBlockProposerWithExpectedPayload interface {
	// BlindedBeaconBlockProposalWithExpectedPayload fetches a blinded proposed beacon block for signing.
	BlindedBeaconBlockProposalWithExpectedPayload(context.Context, phase0.Slot, phase0.BLSSignature, []byte, *builderspec.VersionedSignedBuilderBid) (*api.VersionedBlindedBeaconBlock, error)
}

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
		monitorBeaconBlockProposalCompleted(started, 0, s.chainTime.StartOfSlot(0), "failed")
		return
	}
	if duty == nil {
		log.Error().Msg("Passed nil data structure")
		monitorBeaconBlockProposalCompleted(started, 0, s.chainTime.StartOfSlot(0), "failed")
		return
	}
	span.SetAttributes(attribute.Int64("slot", int64(duty.Slot())))
	log := log.With().Uint64("proposing_slot", uint64(duty.Slot())).Uint64("validator_index", uint64(duty.ValidatorIndex())).Logger()
	log.Trace().Msg("Proposing")

	var zeroSig phase0.BLSSignature
	if duty.RANDAOReveal() == zeroSig {
		log.Error().Msg("Missing RANDAO reveal")
		monitorBeaconBlockProposalCompleted(started, duty.Slot(), s.chainTime.StartOfSlot(duty.Slot()), "failed")
		return
	}

	if duty.Account() == nil {
		log.Error().Msg("Missing account")
		monitorBeaconBlockProposalCompleted(started, duty.Slot(), s.chainTime.StartOfSlot(duty.Slot()), "failed")
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
	span.AddEvent("Ready to propose")
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained graffiti")

	if err := s.proposeBlock(ctx, duty, graffiti); err != nil {
		log.Error().Err(err).Msg("Failed to propose block")
		monitorBeaconBlockProposalCompleted(started, duty.Slot(), s.chainTime.StartOfSlot(duty.Slot()), "failed")
		return
	}

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted proposal")
	monitorBeaconBlockProposalCompleted(started, duty.Slot(), s.chainTime.StartOfSlot(duty.Slot()), "succeeded")
}

// proposeBlock proposes a beacon block.
func (s *Service) proposeBlock(ctx context.Context,
	duty *beaconblockproposer.Duty,
	graffiti []byte,
) error {
	if s.blockAuctioneer != nil {
		// There is a block auctioneer specified, try to propose the block with auction.
		result := s.proposeBlockWithAuction(ctx, duty, graffiti)
		switch result {
		case auctionResultSucceeded:
			monitorBeaconBlockProposalSource("auction")
			return nil
		case auctionResultFailedCanTryWithout:
			log.Warn().Uint64("slot", uint64(duty.Slot())).Msg("Failed to propose with auction; attempting to propose without auction")
		case auctionResultNoBids:
			log.Debug().Uint64("slot", uint64(duty.Slot())).Msg("No auction bids; attempting to propose without auction")
		case auctionResultFailed:
			return errors.New("failed to propose with auction too late in process, cannot fall back")
		}
	}

	err := s.proposeBlockWithoutAuction(ctx, duty, graffiti)
	if err != nil {
		return err
	}

	monitorBeaconBlockProposalSource("direct")
	return nil
}

// proposeBlockWithAuction proposes a block after going through an auction for the blockspace.
func (s *Service) proposeBlockWithAuction(ctx context.Context,
	duty *beaconblockproposer.Duty,
	graffiti []byte,
) auctionResult {
	ctx, span := otel.Tracer("attestantio.vouch.services.beaconblockproposer.standard").Start(ctx, "proposeBlockWithAuction")
	defer span.End()

	log := log.With().Uint64("slot", uint64(duty.Slot())).Logger()

	auctionResults, err := s.auctionBlock(ctx, duty)
	if err != nil {
		log.Error().Err(err).Msg("Failed to auction block")
		return auctionResultFailedCanTryWithout
	}
	if auctionResults.Bid == nil {
		return auctionResultNoBids
	}

	proposal, err := s.obtainBlindedProposal(ctx, duty, graffiti, auctionResults)
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain blinded proposal")
		return auctionResultFailedCanTryWithout
	}

	// Select the relays with the block we need that are capable of unblinding the block.
	providers := make([]builderclient.UnblindedBlockProvider, 0, len(auctionResults.Providers))
	for _, provider := range auctionResults.Providers {
		unblindedBlockProvider, isProvider := provider.(builderclient.UnblindedBlockProvider)
		if !isProvider {
			log.Warn().Msg("Auctioneer cannot unblind the block")
			continue
		}
		providers = append(providers, unblindedBlockProvider)
	}
	if len(providers) == 0 {
		log.Debug().Msg("No relays can unblind the block")
		return auctionResultFailedCanTryWithout
	}
	monitorBestBidRelayCount(len(providers))
	log.Trace().Int("providers", len(providers)).Msg("Obtained relays that can unblind the proposal")

	signedBlindedBlock, err := s.signBlindedProposal(ctx, duty, proposal)
	if err != nil {
		log.Error().Err(err).Msg("Failed to sign blinded proposal")
		return auctionResultFailed
	}

	signedBlock, err := s.unblindBlock(ctx, signedBlindedBlock, providers)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unblind block")
		return auctionResultFailed
	}

	// Submit the block.
	if err := s.beaconBlockSubmitter.SubmitBeaconBlock(ctx, signedBlock); err != nil {
		log.Error().Err(err).Msg("Failed to submit beacon block proposal")
		return auctionResultFailed
	}

	return auctionResultSucceeded
}

func (s *Service) proposeBlockWithoutAuction(ctx context.Context,
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
	log.Trace().Msg("Obtained proposal")

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
	log.Trace().Msg("Signed proposal")

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
	case spec.DataVersionCapella:
		signedBlock.Capella = &capella.SignedBeaconBlock{
			Message:   proposal.Capella,
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

func (s *Service) auctionBlock(ctx context.Context,
	duty *beaconblockproposer.Duty,
) (
	*blockauctioneer.Results,
	error,
) {
	var pubkey phase0.BLSPubKey
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
		return nil, err
	}
	if auctionResults == nil || len(auctionResults.Values) == 0 {
		return &blockauctioneer.Results{}, nil
	}

	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(auctionResults.Bid)
		if err == nil {
			e.RawJSON("header", data).Msg("Obtained best bid; using as header for beacon block proposals")
		}
	}

	return auctionResults, nil
}

func (s *Service) obtainBlindedProposal(ctx context.Context,
	duty *beaconblockproposer.Duty,
	graffiti []byte,
	auctionResults *blockauctioneer.Results,
) (
	*api.VersionedBlindedBeaconBlock,
	error,
) {
	var proposal *api.VersionedBlindedBeaconBlock
	var err error
	if verifyingProvider, isProvider := s.blindedProposalProvider.(BlindedBeaconBlockProposerWithExpectedPayload); isProvider {
		proposal, err = verifyingProvider.BlindedBeaconBlockProposalWithExpectedPayload(ctx, duty.Slot(), duty.RANDAOReveal(), graffiti, auctionResults.Bid)
	} else {
		proposal, err = s.blindedProposalProvider.BlindedBeaconBlockProposal(ctx, duty.Slot(), duty.RANDAOReveal(), graffiti)
	}

	if err != nil {
		return nil, err
	}
	if proposal == nil {
		return nil, errors.New("no proposal obtained")
	}
	if e := log.Trace(); e.Enabled() {
		data, err := json.Marshal(proposal)
		if err == nil {
			e.RawJSON("proposal", data).Msg("Obtained blinded proposal")
		}
	}

	if err := s.validateBlindedBeaconBlockProposal(ctx, duty, auctionResults, proposal); err != nil {
		return nil, err
	}

	return proposal, nil
}

func (*Service) validateBlindedBeaconBlockProposal(_ context.Context,
	duty *beaconblockproposer.Duty,
	auctionResults *blockauctioneer.Results,
	proposal *api.VersionedBlindedBeaconBlock,
) error {
	if proposal == nil {
		return errors.New("obtained nil blinded beacon block proposal")
	}

	proposalSlot, err := proposal.Slot()
	if err != nil {
		return errors.Wrap(err, "failed to obtain proposal slot")
	}
	if proposalSlot != duty.Slot() {
		return errors.New("proposal slot mismatch")
	}

	_, err = proposal.ParentRoot()
	if err != nil {
		return errors.Wrap(err, "failed to obtain proposal parent root")
	}

	_, err = proposal.StateRoot()
	if err != nil {
		return errors.Wrap(err, "failed to obtain proposal state root")
	}

	_, err = proposal.BodyRoot()
	if err != nil {
		return errors.Wrap(err, "failed ot obtain proposal body root")
	}

	proposalTransactionsRoot, err := proposal.TransactionsRoot()
	if err != nil {
		return errors.Wrap(err, "failed to obtain proposal transactions root")
	}
	auctionTransactionsRoot, err := auctionResults.Bid.TransactionsRoot()
	if err != nil {
		return errors.Wrap(err, "failed to obtain auction transactions root")
	}
	if !bytes.Equal(proposalTransactionsRoot[:], auctionTransactionsRoot[:]) {
		log.Debug().
			Uint64("slot", uint64(duty.Slot())).
			Str("proposal_transactions_root", fmt.Sprintf("%#x", proposalTransactionsRoot[:])).
			Str("auction_transactions_root", fmt.Sprintf("%#x", auctionTransactionsRoot[:])).
			Msg("Transactions root mismatch")
		return errors.New("transactions root mismatch")
	}

	return nil
}

func (s *Service) signBlindedProposal(ctx context.Context,
	duty *beaconblockproposer.Duty,
	proposal *api.VersionedBlindedBeaconBlock,
) (
	*api.VersionedSignedBlindedBeaconBlock,
	error,
) {
	parentRoot, err := proposal.ParentRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain parent root")
	}
	stateRoot, err := proposal.StateRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain state root")
	}
	bodyRoot, err := proposal.BodyRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain body root")
	}

	// Sign the block.
	sig, err := s.beaconBlockSigner.SignBeaconBlockProposal(ctx,
		duty.Account(),
		duty.Slot(),
		duty.ValidatorIndex(),
		parentRoot,
		stateRoot,
		bodyRoot)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign blinded beacon block proposal")
	}

	signedBlindedBlock := &api.VersionedSignedBlindedBeaconBlock{
		Version: proposal.Version,
	}
	switch signedBlindedBlock.Version {
	case spec.DataVersionBellatrix:
		signedBlindedBlock.Bellatrix = &apiv1bellatrix.SignedBlindedBeaconBlock{
			Message:   proposal.Bellatrix,
			Signature: sig,
		}
	case spec.DataVersionCapella:
		signedBlindedBlock.Capella = &apiv1capella.SignedBlindedBeaconBlock{
			Message:   proposal.Capella,
			Signature: sig,
		}
	default:
		return nil, fmt.Errorf("unknown proposal version %v", signedBlindedBlock.Version)
	}

	return signedBlindedBlock, nil
}

func (*Service) unblindBlock(ctx context.Context,
	block *api.VersionedSignedBlindedBeaconBlock,
	providers []builderclient.UnblindedBlockProvider,
) (
	*spec.VersionedSignedBeaconBlock,
	error,
) {
	// We do not create a cancelable context, as if we do cancel the later-returning providers they will mark themselves
	// as failed even if they are just running a little slow, which isn't a useful thing to do.  Instead, we use a
	// semaphore to track if a signed block has been returned by any provider.
	sem := semaphore.NewWeighted(1)

	respCh := make(chan *spec.VersionedSignedBeaconBlock, 1)
	for _, provider := range providers {
		go func(ctx context.Context, provider builderclient.UnblindedBlockProvider, ch chan *spec.VersionedSignedBeaconBlock) {
			log := log.With().Str("provider", provider.Address()).Logger()
			log.Trace().Msg("Unblinding block with provider")

			// As we cannot fall back we move to a retry system.
			retryInterval := 500 * time.Millisecond

			var signedBlock *spec.VersionedSignedBeaconBlock
			var err error
			for retries := 3; retries > 0; retries-- {
				// Unblind the blinded block.
				signedBlock, err = provider.UnblindBlock(ctx, block)

				if !sem.TryAcquire(1) {
					// We failed to acquire the semaphore, which means another relay has responded already.
					// As such, we can leave without going any further.
					log.Trace().Msg("Another relay has already responded")
					return
				}
				sem.Release(1)

				if err != nil {
					log.Debug().Err(err).Int("retries", retries).Msg("Failed to unblind block")
					time.Sleep(retryInterval)
					continue
				}
				break
			}
			if signedBlock == nil {
				log.Debug().Msg("No signed block received")
				return
			}

			log.Trace().Msg("Unblinded block")
			// Acquire the semaphore to confirm that a block has been received.
			// Use TryAcquire in case two proviers return the block at the same time.
			sem.TryAcquire(1)
			ch <- signedBlock
		}(ctx, provider, respCh)
	}

	select {
	case <-ctx.Done():
		log.Warn().Msg("Failed to obtain unblinded block")
		return nil, errors.New("failed to obtain unblinded block")
	case signedBlock := <-respCh:
		if e := log.Trace(); e.Enabled() {
			data, err := json.Marshal(signedBlock)
			if err == nil {
				log.Trace().RawJSON("signed_block", data).Msg("Recomposed block to submit")
			}
		}
		return signedBlock, nil
	}
}
