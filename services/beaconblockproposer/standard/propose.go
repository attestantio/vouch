// Copyright © 2020 - 2024 Attestant Limited.
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
	"time"

	"github.com/attestantio/go-block-relay/services/blockauctioneer"
	builderclient "github.com/attestantio/go-builder-client"
	builderapi "github.com/attestantio/go-builder-client/api"
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
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
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

// Propose proposes a block.
func (s *Service) Propose(ctx context.Context, duty *beaconblockproposer.Duty) {
	ctx, span := otel.Tracer("attestantio.vouch.services.beaconblockproposer.standard").Start(ctx, "Propose")
	defer span.End()
	started := time.Now()

	slot, err := validateDuty(duty)
	if err != nil {
		s.log.Error().Err(err).Msg("Invalid duty")
		monitorBeaconBlockProposalCompleted(started, slot, s.chainTime.StartOfSlot(slot), "failed")
		return
	}
	span.SetAttributes(attribute.Int64("slot", util.SlotToInt64(slot)))
	log := s.log.With().Uint64("proposing_slot", uint64(slot)).Uint64("validator_index", uint64(duty.ValidatorIndex())).Logger()
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
				s.log.Warn().Err(err).Msg("Failed to obtain node client; not updating graffiti")
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
	var auctionResults *blockauctioneer.Results
	var err error
	if s.blockAuctioneer != nil {
		auctionResults, err = s.auctionBlock(ctx, duty)
		if err != nil {
			s.log.Error().Err(err).Msg("Failed to auction block")
		} else {
			monitorBestBidRelayCount(len(auctionResults.Providers))
		}
	}

	proposalResponse, err := s.proposalProvider.Proposal(ctx, &api.ProposalOpts{
		Slot:               duty.Slot(),
		RandaoReveal:       duty.RANDAOReveal(),
		Graffiti:           graffiti,
		BuilderBoostFactor: &s.builderBoostFactor,
	})
	if err != nil {
		return errors.Wrap(err, "failed to obtain proposal")
	}
	proposal := proposalResponse.Data
	if proposal.Blinded {
		monitorBeaconBlockProposalSource("relay")
	} else {
		monitorBeaconBlockProposalSource("local")
	}

	if err := s.confirmProposalData(ctx, proposal, duty); err != nil {
		return err
	}

	signedProposal, err := s.signProposalData(ctx, proposal, duty)
	if err != nil {
		return err
	}

	if signedProposal.Blinded {
		// Select the relays to unblind the proposal.
		providers := make([]builderclient.UnblindedProposalProvider, 0, len(auctionResults.AllProviders))
		unblindingCandidates := auctionResults.Providers
		if len(unblindingCandidates) == 0 || s.unblindFromAllRelays {
			s.log.Trace().Int("providers", len(auctionResults.AllProviders)).Msg("Unblinding from all providers")
			unblindingCandidates = auctionResults.AllProviders
		}

		for _, provider := range unblindingCandidates {
			unblindedProposalProvider, isProvider := provider.(builderclient.UnblindedProposalProvider)
			if !isProvider {
				s.log.Warn().Str("provider", provider.Name()).Msg("Auctioneer cannot unblind the proposal")
				continue
			}
			providers = append(providers, unblindedProposalProvider)
		}
		if len(providers) == 0 {
			return errors.New("no relays to unblind the block")
		}

		s.log.Trace().Int("providers", len(providers)).Msg("Obtained relays that can unblind the proposal")
		if err := s.unblindProposal(ctx, signedProposal, providers); err != nil {
			return errors.Wrap(err, "failed to unblind block")
		}
	}

	if err := s.proposalSubmitter.SubmitProposal(ctx, signedProposal); err != nil {
		return errors.Wrap(err, "failed to submit proposal")
	}

	return nil
}

func (*Service) confirmProposalData(_ context.Context,
	proposal *api.VersionedProposal,
	duty *beaconblockproposer.Duty,
) error {
	proposalSlot, err := proposal.Slot()
	if err != nil {
		return errors.Wrap(err, "failed to obtain proposal slot")
	}
	if proposalSlot != duty.Slot() {
		return errors.New("proposal data for incorrect slot")
	}

	// RANDAO reveal can be different in DVT situations, so do not check it.  It wil have already been checked by the underlying
	// library that obtained the proposal, which is DVT-aware.

	// Graffiti can be different if the consensus nodes rewrites it, e.g. to add node version information, so do not check it.

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
		Version:        proposal.Version,
		Blinded:        proposal.Blinded,
		ExecutionValue: proposal.ExecutionValue,
		ConsensusValue: proposal.ConsensusValue,
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
		if proposal.Blinded {
			signedProposal.BellatrixBlinded = &apiv1bellatrix.SignedBlindedBeaconBlock{
				Message:   proposal.BellatrixBlinded,
				Signature: sig,
			}
		} else {
			signedProposal.Bellatrix = &bellatrix.SignedBeaconBlock{
				Message:   proposal.Bellatrix,
				Signature: sig,
			}
		}
	case spec.DataVersionCapella:
		if proposal.Blinded {
			signedProposal.CapellaBlinded = &apiv1capella.SignedBlindedBeaconBlock{
				Message:   proposal.CapellaBlinded,
				Signature: sig,
			}
		} else {
			signedProposal.Capella = &capella.SignedBeaconBlock{
				Message:   proposal.Capella,
				Signature: sig,
			}
		}
	case spec.DataVersionDeneb:
		if proposal.Blinded {
			signedProposal.DenebBlinded = &apiv1deneb.SignedBlindedBeaconBlock{
				Message:   proposal.DenebBlinded,
				Signature: sig,
			}
		} else {
			signedProposal.Deneb = &apiv1deneb.SignedBlockContents{
				SignedBlock: &deneb.SignedBeaconBlock{
					Message:   proposal.Deneb.Block,
					Signature: sig,
				},
				KZGProofs: proposal.Deneb.KZGProofs,
				Blobs:     proposal.Deneb.Blobs,
			}
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
	hash, height := s.executionChainHeadProvider.ExecutionChainHead(ctx)
	s.log.Trace().Str("hash", fmt.Sprintf("%#x", hash)).Uint64("height", height).Msg("Current execution chain state")
	auctionResults, err := s.blockAuctioneer.AuctionBlock(ctx,
		duty.Slot(),
		hash,
		util.ValidatorPubkey(duty.Account()))
	if err != nil {
		return nil, err
	}

	if e := s.log.Trace(); e.Enabled() {
		data, err := json.Marshal(auctionResults)
		if err == nil {
			e.RawJSON("results", data).Msg("Auction complete")
		}
	}

	return auctionResults, nil
}

func (s *Service) unblindProposal(ctx context.Context,
	proposal *api.VersionedSignedProposal,
	providers []builderclient.UnblindedProposalProvider,
) error {
	// We do not create a cancelable context, as if we do cancel the later-returning providers they will mark themselves
	// as failed even if they are just running a little slow, which isn't a useful thing to do.  Instead, we use a
	// semaphore to track if a signed block has been returned by any provider.
	sem := semaphore.NewWeighted(1)

	respCh := make(chan *api.VersionedSignedProposal, 1)
	for _, provider := range providers {
		go func(ctx context.Context, provider builderclient.UnblindedProposalProvider, ch chan *api.VersionedSignedProposal) {
			log := s.log.With().Str("provider", provider.Address()).Logger()
			log.Trace().Msg("Unblinding block with provider")

			// As we cannot fall back we move to a retry system.
			retryInterval := 250 * time.Millisecond

			var signedProposalResponse *builderapi.Response[*api.VersionedSignedProposal]
			var err error
			for retries := 3; retries > 0; retries-- {
				// Unblind the blinded block.
				signedProposalResponse, err = provider.UnblindProposal(ctx, &builderapi.UnblindProposalOpts{
					Proposal: &api.VersionedSignedBlindedProposal{
						Version:   proposal.Version,
						Bellatrix: proposal.BellatrixBlinded,
						Capella:   proposal.CapellaBlinded,
						Deneb:     proposal.DenebBlinded,
					},
				})

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
			if signedProposalResponse == nil {
				log.Debug().Msg("No signed block received")
				return
			}

			log.Trace().Msg("Unblinded block")
			// Acquire the semaphore to confirm that a block has been received.
			// Use TryAcquire in case two providers return the block at the same time.
			sem.TryAcquire(1)
			ch <- signedProposalResponse.Data
		}(ctx, provider, respCh)
	}

	select {
	case <-ctx.Done():
		s.log.Warn().Msg("Failed to obtain unblinded block")
		return errors.New("failed to obtain unblinded block")
	case signedBlock := <-respCh:
		if e := s.log.Trace(); e.Enabled() {
			data, err := json.Marshal(signedBlock)
			if err == nil {
				e.RawJSON("signed_block", data).Msg("Recomposed block to submit")
			}
		}
		switch proposal.Version {
		case spec.DataVersionBellatrix:
			proposal.BellatrixBlinded = nil
			proposal.Bellatrix = signedBlock.Bellatrix
		case spec.DataVersionCapella:
			proposal.CapellaBlinded = nil
			proposal.Capella = signedBlock.Capella
		case spec.DataVersionDeneb:
			proposal.DenebBlinded = nil
			proposal.Deneb = signedBlock.Deneb
		default:
			return fmt.Errorf("unsupported version %v", proposal.Version)
		}
		proposal.Blinded = false

		return nil
	}
}
