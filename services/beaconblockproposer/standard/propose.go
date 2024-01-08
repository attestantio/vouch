// Copyright © 2020 - 2023 Attestant Limited.
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
	"strings"
	"sync"
	"time"

	"github.com/attestantio/go-block-relay/services/blockauctioneer"
	builderclient "github.com/attestantio/go-builder-client"
	builderspec "github.com/attestantio/go-builder-client/spec"
	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	apiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/semaphore"
)

type BlindedProposerWithExpectedPayload interface {
	// BlindedProposalWithExpectedPayload fetches a blinded proposed beacon block for signing.
	BlindedProposalWithExpectedPayload(context.Context,
		phase0.Slot,
		phase0.BLSSignature,
		[]byte,
		*builderspec.VersionedSignedBuilderBid,
	) (
		*api.VersionedBlindedProposal,
		error,
	)
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
	slot, err := validateDuty(duty)
	if err != nil {
		log.Error().Err(err).Msg("Invalid duty")
		monitorBeaconBlockProposalCompleted(started, slot, s.chainTime.StartOfSlot(slot), "failed")
		return
	}
	span.SetAttributes(attribute.Int64("slot", int64(slot)))
	log := log.With().Uint64("proposing_slot", uint64(slot)).Uint64("validator_index", uint64(duty.ValidatorIndex())).Logger()
	log.Trace().Msg("Proposing")

	graffiti, err := s.obtainGraffiti(ctx, slot, duty.ValidatorIndex())
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain graffiti")
		graffiti = [32]byte{}
	}

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained graffiti")
	span.AddEvent("Ready to propose")

	if err := s.proposeBlock(ctx, duty, graffiti); err != nil {
		log.Error().Err(err).Msg("Failed to propose block")
		monitorBeaconBlockProposalCompleted(started, slot, s.chainTime.StartOfSlot(slot), "failed")
		return
	}

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted proposal")
	monitorBeaconBlockProposalCompleted(started, slot, s.chainTime.StartOfSlot(slot), "succeeded")
}

// validateDuty validates that the information supplied to us in a duty is suitable for proposing.
func validateDuty(duty *beaconblockproposer.Duty) (phase0.Slot, error) {
	if duty == nil {
		return 0, errors.New("no duty supplied")
	}

	zeroSig := phase0.BLSSignature{}
	randaoReveal := duty.RANDAOReveal()
	if bytes.Equal(randaoReveal[:], zeroSig[:]) {
		return duty.Slot(), errors.New("duty missing RANDAO reveal")
	}

	if duty.Account() == nil {
		return duty.Slot(), errors.New("duty missing account")
	}

	return duty.Slot(), nil
}

// obtainGraffiti obtains the graffiti for the proposal.
func (s *Service) obtainGraffiti(ctx context.Context,
	slot phase0.Slot,
	validatorIndex phase0.ValidatorIndex,
) (
	[32]byte,
	error,
) {
	var res [32]byte

	if s.graffitiProvider == nil {
		return res, nil
	}

	graffiti, err := s.graffitiProvider.Graffiti(ctx, slot, validatorIndex)
	if err != nil {
		return res, errors.Wrap(err, "graffiti provider failed")
	}

	if bytes.Contains(graffiti, []byte("{{CLIENT}}")) {
		if nodeClientProvider, isProvider := s.proposalProvider.(consensusclient.NodeClientProvider); isProvider {
			nodeClientResponse, err := nodeClientProvider.NodeClient(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to obtain node client; not updating graffiti")
			} else {
				graffiti = bytes.ReplaceAll(graffiti, []byte("{{CLIENT}}"), []byte(nodeClientResponse.Data))
			}
		}
	}

	copy(res[:], graffiti)

	return res, nil
}

// proposeBlock proposes a beacon block.
func (s *Service) proposeBlock(ctx context.Context,
	duty *beaconblockproposer.Duty,
	graffiti [32]byte,
) error {
	// Pre-fetch an unblinded block in parallel with the auction process.
	// This ensures that we are ready to propose as quickly as possible if the auction is unsuccessful.
	var wg sync.WaitGroup
	var proposal *api.VersionedProposal
	wg.Add(1)
	go func(ctx context.Context, duty *beaconblockproposer.Duty, graffiti [32]byte) {
		var err error
		proposalResponse, err := s.proposalProvider.Proposal(ctx, &api.ProposalOpts{
			Slot:         duty.Slot(),
			RandaoReveal: duty.RANDAOReveal(),
			Graffiti:     graffiti,
		})
		if err != nil {
			log.Warn().Err(err).Msg("Failed to pre-obtain proposal data")
			return
		}
		proposal = proposalResponse.Data
		log.Trace().Msg("Pre-obtained proposal")
		wg.Done()
	}(ctx, duty, graffiti)

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

	wg.Wait()

	err := s.proposeBlockWithoutAuction(ctx, proposal, duty, graffiti)
	if err != nil {
		return err
	}

	monitorBeaconBlockProposalSource("direct")
	return nil
}

// proposeBlockWithAuction proposes a block after going through an auction for the blockspace.
func (s *Service) proposeBlockWithAuction(ctx context.Context,
	duty *beaconblockproposer.Duty,
	graffiti [32]byte,
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
	monitorBestBidRelayCount(len(auctionResults.Providers))

	proposal, err := s.obtainBlindedProposal(ctx, duty, graffiti, auctionResults)
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain blinded proposal")
		return auctionResultFailedCanTryWithout
	}

	// Select the relays to unblind the proposal.
	providers := make([]builderclient.UnblindedProposalProvider, 0, len(auctionResults.AllProviders))
	var unblindingCandidates []builderclient.BuilderBidProvider
	if s.unblindFromAllRelays {
		unblindingCandidates = auctionResults.AllProviders
	} else {
		unblindingCandidates = auctionResults.Providers
	}
	for _, provider := range unblindingCandidates {
		unblindedProposalProvider, isProvider := provider.(builderclient.UnblindedProposalProvider)
		if !isProvider {
			log.Warn().Str("provider", provider.Name()).Msg("Auctioneer cannot unblind the proposal")
			continue
		}
		providers = append(providers, unblindedProposalProvider)
	}
	if len(providers) == 0 {
		log.Debug().Msg("No relays can unblind the block")
		return auctionResultFailedCanTryWithout
	}
	log.Trace().Int("providers", len(providers)).Msg("Obtained relays that can unblind the proposal")

	signedBlindedBlock, err := s.signBlindedProposal(ctx, duty, proposal)
	if err != nil {
		log.Error().Err(err).Msg("Failed to sign blinded proposal")
		return auctionResultFailed
	}

	signedProposal, err := s.unblindBlock(ctx, signedBlindedBlock, providers)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unblind block")
		return auctionResultFailed
	}

	// Submit the proposal.
	if err := s.proposalSubmitter.SubmitProposal(ctx, signedProposal); err != nil {
		log.Error().Err(err).Msg("Failed to submit beacon block proposal")
		return auctionResultFailed
	}

	return auctionResultSucceeded
}

func (s *Service) proposeBlockWithoutAuction(ctx context.Context,
	proposal *api.VersionedProposal,
	duty *beaconblockproposer.Duty,
	graffiti [32]byte,
) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.beaconblockproposer.standard").Start(ctx, "proposeBlockWithoutAuction")
	defer span.End()

	if proposal == nil {
		proposalResponse, err := s.proposalProvider.Proposal(ctx, &api.ProposalOpts{
			Slot:         duty.Slot(),
			RandaoReveal: duty.RANDAOReveal(),
			Graffiti:     graffiti,
		})
		if err != nil {
			return errors.Wrap(err, "failed to obtain proposal data")
		}
		proposal = proposalResponse.Data
		log.Trace().Msg("Obtained proposal")
	}

	if err := s.confirmProposalData(ctx, proposal, duty, graffiti); err != nil {
		return err
	}

	signedProposal, err := s.signProposalData(ctx, proposal, duty)
	if err != nil {
		return err
	}

	if err := s.proposalSubmitter.SubmitProposal(ctx, signedProposal); err != nil {
		return errors.Wrap(err, "failed to submit proposal")
	}

	return nil
}

func (*Service) confirmProposalData(_ context.Context,
	proposal *api.VersionedProposal,
	duty *beaconblockproposer.Duty,
	graffiti [32]byte,
) error {
	proposalSlot, err := proposal.Slot()
	if err != nil {
		return errors.Wrap(err, "failed to obtain proposal slot")
	}
	if proposalSlot != duty.Slot() {
		return errors.New("proposal data for incorrect slot")
	}

	proposalGraffiti, err := proposal.Graffiti()
	if err != nil {
		return errors.Wrap(err, "failed to obtain proposal graffiti")
	}
	if !bytes.Equal(proposalGraffiti[:], graffiti[:]) {
		return errors.New("proposal data contains incorrect graffiti")
	}

	return nil
}

func (s *Service) signProposalData(ctx context.Context,
	proposal *api.VersionedProposal,
	duty *beaconblockproposer.Duty,
) (
	*api.VersionedSignedProposal,
	error,
) {
	bodyRoot, err := proposal.BodyRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to calculate hash tree root of block body proposal")
	}

	parentRoot, err := proposal.ParentRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain parent root of block proposal")
	}

	stateRoot, err := proposal.StateRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain state root of block proposal")
	}

	sig, err := s.beaconBlockSigner.SignBeaconBlockProposal(ctx,
		duty.Account(),
		duty.Slot(),
		duty.ValidatorIndex(),
		parentRoot,
		stateRoot,
		bodyRoot)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign beacon block proposal")
	}

	signedProposal := &api.VersionedSignedProposal{
		Version: proposal.Version,
	}

	switch proposal.Version {
	case spec.DataVersionPhase0:
		signedProposal.Phase0 = &phase0.SignedBeaconBlock{
			Message:   proposal.Phase0,
			Signature: sig,
		}
	case spec.DataVersionAltair:
		signedProposal.Altair = &altair.SignedBeaconBlock{
			Message:   proposal.Altair,
			Signature: sig,
		}
	case spec.DataVersionBellatrix:
		signedProposal.Bellatrix = &bellatrix.SignedBeaconBlock{
			Message:   proposal.Bellatrix,
			Signature: sig,
		}
	case spec.DataVersionCapella:
		signedProposal.Capella = &capella.SignedBeaconBlock{
			Message:   proposal.Capella,
			Signature: sig,
		}
	case spec.DataVersionDeneb:
		signedProposal.Deneb = &apiv1deneb.SignedBlockContents{
			SignedBlock: &deneb.SignedBeaconBlock{
				Message:   proposal.Deneb.Block,
				Signature: sig,
			},
			KZGProofs: proposal.Deneb.KZGProofs,
			Blobs:     proposal.Deneb.Blobs,
		}
	default:
		return nil, errors.New("unhandled proposal version")
	}

	return signedProposal, nil
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
	graffiti [32]byte,
	auctionResults *blockauctioneer.Results,
) (
	*api.VersionedBlindedProposal,
	error,
) {
	var proposal *api.VersionedBlindedProposal
	var err error
	if verifyingProvider, isProvider := s.blindedProposalProvider.(BlindedProposerWithExpectedPayload); isProvider {
		proposal, err = verifyingProvider.BlindedProposalWithExpectedPayload(ctx, duty.Slot(), duty.RANDAOReveal(), graffiti[:], auctionResults.Bid)
	} else {
		proposalResponse, err := s.blindedProposalProvider.BlindedProposal(ctx, &api.BlindedProposalOpts{
			Slot:         duty.Slot(),
			RandaoReveal: duty.RANDAOReveal(),
			Graffiti:     graffiti,
		})
		if err != nil {
			return nil, err
		}
		proposal = proposalResponse.Data
	}
	if err != nil {
		return nil, err
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
	proposal *api.VersionedBlindedProposal,
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
	proposal *api.VersionedBlindedProposal,
) (
	*api.VersionedSignedBlindedProposal,
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

	signedProposal := &api.VersionedSignedBlindedProposal{
		Version: proposal.Version,
	}
	switch signedProposal.Version {
	case spec.DataVersionBellatrix:
		signedProposal.Bellatrix = &apiv1bellatrix.SignedBlindedBeaconBlock{
			Message:   proposal.Bellatrix,
			Signature: sig,
		}
	case spec.DataVersionCapella:
		signedProposal.Capella = &apiv1capella.SignedBlindedBeaconBlock{
			Message:   proposal.Capella,
			Signature: sig,
		}
	case spec.DataVersionDeneb:
		signedProposal.Deneb = &apiv1deneb.SignedBlindedBeaconBlock{
			Message:   proposal.Deneb,
			Signature: sig,
		}
	default:
		return nil, fmt.Errorf("unknown proposal version %v", signedProposal.Version)
	}

	return signedProposal, nil
}

func (*Service) unblindBlock(ctx context.Context,
	proposal *api.VersionedSignedBlindedProposal,
	providers []builderclient.UnblindedProposalProvider,
) (
	*api.VersionedSignedProposal,
	error,
) {
	// We do not create a cancelable context, as if we do cancel the later-returning providers they will mark themselves
	// as failed even if they are just running a little slow, which isn't a useful thing to do.  Instead, we use a
	// semaphore to track if a signed block has been returned by any provider.
	sem := semaphore.NewWeighted(1)

	respCh := make(chan *api.VersionedSignedProposal, 1)
	for _, provider := range providers {
		go func(ctx context.Context, provider builderclient.UnblindedProposalProvider, ch chan *api.VersionedSignedProposal) {
			log := log.With().Str("provider", provider.Address()).Logger()
			log.Trace().Msg("Unblinding block with provider")

			// As we cannot fall back we move to a retry system.
			retryInterval := 250 * time.Millisecond

			var signedProposal *api.VersionedSignedProposal
			var err error
			for retries := 3; retries > 0; retries-- {
				// Unblind the blinded block.
				signedProposal, err = provider.UnblindProposal(ctx, proposal)

				if !sem.TryAcquire(1) {
					// We failed to acquire the semaphore, which means another relay has responded already.
					// As such, we can leave without going any further.
					log.Trace().Msg("Another relay has already responded")
					return
				}
				sem.Release(1)

				if err != nil {
					log.Debug().Err(err).Int("retries", retries).Msg("Failed to unblind block")
					if strings.Contains(err.Error(), "POST failed with status 400") {
						log.Debug().Msg("Responded with 400; not trying again as relay does not know of the payload")
						return
					}
					time.Sleep(retryInterval)
					continue
				}
				break
			}
			if signedProposal == nil {
				log.Debug().Msg("No signed block received")
				return
			}

			log.Trace().Msg("Unblinded block")
			// Acquire the semaphore to confirm that a block has been received.
			// Use TryAcquire in case two providers return the block at the same time.
			sem.TryAcquire(1)
			ch <- signedProposal
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
				e.RawJSON("signed_block", data).Msg("Recomposed block to submit")
			}
		}
		return signedBlock, nil
	}
}
