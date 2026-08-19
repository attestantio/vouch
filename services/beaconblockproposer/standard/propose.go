// Copyright © 2020 - 2026 Attestant Limited.
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
	"math"
	"strings"
	"time"

	"github.com/attestantio/go-block-relay/services/blockauctioneer"
	builderclient "github.com/attestantio/go-builder-client"
	builderapi "github.com/attestantio/go-builder-client/api"
	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	apiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	apiv1electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	apiv1fulu "github.com/attestantio/go-eth2-client/api/v1/fulu"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// Propose proposes a block.
func (s *Service) Propose(ctx context.Context, duty *beaconblockproposer.Duty) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.beaconblockproposer.standard").Start(ctx, "Propose")
	defer span.End()
	started := time.Now()

	slot, err := validateDuty(duty)
	if err != nil {
		monitorBeaconBlockProposalCompleted(started, slot, s.chainTime.StartOfSlot(slot), "failed")

		return err
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
		monitorBeaconBlockProposalCompleted(started, slot, s.chainTime.StartOfSlot(slot), "failed")

		return errors.Wrap(err, "failed to propose block")
	}

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted proposal")
	monitorBeaconBlockProposalCompleted(started, slot, s.chainTime.StartOfSlot(slot), "succeeded")

	return nil
}

// validateDuty validates that the information supplied to us in a duty is suitable for proposing.
func validateDuty(duty *beaconblockproposer.Duty) (phase0.Slot, error) {
	if duty == nil {
		return 0, errors.New("no duty supplied")
	}

	if duty.RANDAOReveal().IsZero() {
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
	if s.chainTime.SlotToEpoch(duty.Slot()) >= s.chainTime.HardForkEpoch(ctx, "GLOAS_FORK_EPOCH") {
		return s.proposeEPBSBlock(ctx, duty, graffiti)
	}

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
		providers, err := s.unblindingProviders(auctionResults)
		if err != nil {
			return err
		}
		if err := s.unblindProposal(ctx, signedProposal, providers); err != nil {
			return errors.Wrap(err, "failed to unblind block")
		}
	}

	if err := s.proposalSubmitter.SubmitProposal(ctx, signedProposal); err != nil {
		return errors.Wrap(err, "failed to submit proposal")
	}

	return nil
}

// unblindingProviders returns the relays that can unblind a proposal.
func (s *Service) unblindingProviders(auctionResults *blockauctioneer.Results) ([]builderclient.UnblindedProposalProvider, error) {
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
		return nil, errors.New("no relays to unblind the block")
	}

	s.log.Trace().Int("providers", len(providers)).Msg("Obtained relays that can unblind the proposal")

	return providers, nil
}

// proposeEPBSBlock proposes a Gloas block.
// skipcq: GO-R1005
func (s *Service) proposeEPBSBlock(ctx context.Context,
	duty *beaconblockproposer.Duty,
	graffiti [32]byte,
) error {
	if s.executionPayloadEnvelopeSigner == nil {
		return errors.New("no execution payload envelope signer available")
	}
	if s.executionPayloadEnvelopeSubmitter == nil {
		return errors.New("no execution payload envelope submitter available")
	}
	if s.blockAuctioneer != nil {
		s.log.Warn().Msg("Ignoring configured block auctioneer on Gloas proposal path")
	}
	if s.builderBoostFactor != 0 {
		s.log.Warn().Msg("Ignoring non-default builder boost factor on Gloas proposal path")
	}

	// A Gloas block never carries an execution payload: it commits to a bid, and the
	// payload is revealed separately as an envelope.  IncludePayload selects whether
	// that envelope travels back with the block or stays cached on the producing node,
	// so asking for it is what keeps the reveal publishable through any beacon node
	// rather than only the one that built the payload.
	includePayload := true
	// Force local building.
	selfBuildBoostFactor := uint64(0)
	proposalResponse, err := s.proposalProvider.EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot:               duty.Slot(),
		RandaoReveal:       duty.RANDAOReveal(),
		Graffiti:           graffiti,
		IncludePayload:     &includePayload,
		BuilderBoostFactor: &selfBuildBoostFactor,
	})
	if err != nil {
		return errors.Wrap(err, "failed to obtain ePBS proposal")
	}
	proposal := proposalResponse.Data
	if !proposal.ExecutionPayloadIncluded {
		return errors.New("ePBS proposal excludes requested execution payload")
	}

	if err := s.confirmEPBSProposalData(ctx, proposal, duty); err != nil {
		return err
	}

	envelope, bodyRoot, err := s.epbsProposalEnvelope(proposal)
	if err != nil {
		return err
	}
	log := s.log.With().Str("beacon_block_root", envelope.BeaconBlockRoot.String()).Logger()

	var signedProposal *api.VersionedSignedProposal
	var signature phase0.BLSSignature
	signingGroup, signingCtx := errgroup.WithContext(ctx)
	signingGroup.Go(func() error {
		var err error
		signedProposal, err = s.signEPBSProposalData(signingCtx, proposal, duty, bodyRoot)

		return err
	})
	signingGroup.Go(func() error {
		var err error
		signature, err = s.executionPayloadEnvelopeSigner.SignExecutionPayloadEnvelope(signingCtx, duty.Account(), duty.Slot(), envelope)
		if err != nil {
			return errors.Wrap(err, "failed to sign execution payload envelope")
		}

		return nil
	})
	if err := signingGroup.Wait(); err != nil {
		return err
	}
	kzgProofs, err := proposal.KZGProofs()
	if err != nil {
		return errors.Wrap(err, "failed to obtain execution payload envelope KZG proofs")
	}
	blobs, err := proposal.Blobs()
	if err != nil {
		return errors.Wrap(err, "failed to obtain execution payload envelope blobs")
	}

	if err := s.proposalSubmitter.SubmitProposal(ctx, signedProposal); err != nil {
		log.Warn().Err(err).Time("proposal_submission_completed_at", time.Now()).Msg("Failed to submit ePBS beacon block proposal")

		return errors.Wrap(err, "failed to submit proposal")
	}
	log.Trace().Time("proposal_submission_completed_at", time.Now()).Msg("Submitted ePBS beacon block proposal")

	envelopeSubmissionOpts := &api.SubmitExecutionPayloadEnvelopeOpts{
		SignedExecutionPayloadEnvelope: &spec.VersionedSignedExecutionPayloadEnvelope{
			Version: spec.DataVersionGloas,
			Gloas: &gloas.SignedExecutionPayloadEnvelope{
				Message:   envelope,
				Signature: signature,
			},
		},
		KZGProofs: kzgProofs,
		Blobs:     blobs,
	}
	var envelopeSubmissionErr error
	for attempt := 1; attempt <= 3; attempt++ {
		log.Trace().Int("attempt", attempt).Msg("Submitting execution payload envelope")
		envelopeSubmissionErr = s.executionPayloadEnvelopeSubmitter.SubmitExecutionPayloadEnvelope(ctx, envelopeSubmissionOpts)
		if envelopeSubmissionErr == nil {
			log.Trace().Int("attempt", attempt).Bool("envelope_submission_succeeded", true).Msg("Execution payload envelope submission attempt completed")

			break
		}
		log.Warn().Err(envelopeSubmissionErr).Int("attempt", attempt).Bool("envelope_submission_succeeded", false).Msg("Execution payload envelope submission attempt completed")
		log.Warn().Err(envelopeSubmissionErr).Int("attempts_remaining", 3-attempt).Msg("Failed to submit execution payload envelope after block publication")
		if attempt < 3 {
			select {
			case <-ctx.Done():
				log.Warn().Err(ctx.Err()).Str("status", "failed").Bool("envelope_submission_succeeded", false).Msg("Execution payload envelope submission completed")

				return errors.Wrap(ctx.Err(), "failed to submit execution payload envelope after block publication")
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	if envelopeSubmissionErr == nil {
		log.Trace().Bool("envelope_submission_succeeded", true).Msg("Execution payload envelope submission completed")
	} else {
		log.Warn().Err(envelopeSubmissionErr).Bool("envelope_submission_succeeded", false).Msg("Execution payload envelope submission completed")
	}
	if envelopeSubmissionErr != nil {
		return errors.Wrap(envelopeSubmissionErr, "failed to submit execution payload envelope after block publication")
	}
	monitorBeaconBlockProposalSource("local")

	return nil
}

// epbsProposalEnvelope obtains the execution payload envelope and body root for a proposal,
// confirming that the envelope is for the proposed block and pays a fee recipient.
func (*Service) epbsProposalEnvelope(proposal *api.VersionedEPBSProposal) (*gloas.ExecutionPayloadEnvelope, phase0.Root, error) {
	envelope, err := proposal.ExecutionPayloadEnvelope()
	if err != nil {
		return nil, phase0.Root{}, errors.Wrap(err, "failed to obtain execution payload envelope")
	}
	if envelope.Payload == nil {
		return nil, phase0.Root{}, errors.New("ePBS execution payload envelope has no payload")
	}
	// The bid's fee recipient is the one the strategies check, but a self-built bid pays
	// nothing: the spec requires bid.value to be zero and records no builder payment for
	// it.  The payload's own fee recipient collects the slot's priority fees and MEV, so
	// it is the one that has to be checked before this envelope is signed.
	if envelope.Payload.FeeRecipient.IsZero() {
		return nil, phase0.Root{}, errors.New("ePBS execution payload envelope has 0 fee recipient")
	}
	if proposal.GloasContents == nil || proposal.GloasContents.Block == nil || proposal.GloasContents.Block.Body == nil || proposal.GloasContents.Block.Body.SignedExecutionPayloadBid == nil || proposal.GloasContents.Block.Body.SignedExecutionPayloadBid.Message == nil {
		return nil, phase0.Root{}, errors.New("ePBS proposal has no execution payload bid")
	}
	if proposal.GloasContents.Block.Body.SignedExecutionPayloadBid.Message.BuilderIndex != gloas.BuilderIndex(math.MaxUint64) {
		return nil, phase0.Root{}, errors.New("ePBS execution payload bid is not self-built")
	}
	if envelope.BuilderIndex != proposal.GloasContents.Block.Body.SignedExecutionPayloadBid.Message.BuilderIndex {
		return nil, phase0.Root{}, errors.New("ePBS execution payload envelope is for incorrect builder index")
	}
	bodyRoot, err := proposal.BodyRoot()
	if err != nil {
		return nil, phase0.Root{}, errors.Wrap(err, "failed to calculate hash tree root of ePBS block body")
	}
	// Use proposal.Root() rather than hashing GloasContents.Block ourselves: the
	// generated block hasher inlines mainnet preset sizes, so it is wrong on any
	// other preset.  Root() derives the block root from the same body root that
	// is signed below, and is the same derivation the beacon node client used to
	// check the envelope, so this guard and the signature cannot disagree.
	blockRoot, err := proposal.Root()
	if err != nil {
		return nil, phase0.Root{}, errors.Wrap(err, "failed to calculate hash tree root of ePBS block")
	}
	if blockRoot != envelope.BeaconBlockRoot {
		return nil, phase0.Root{}, errors.New("ePBS execution payload envelope is for incorrect block")
	}

	return envelope, bodyRoot, nil
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

func (*Service) confirmEPBSProposalData(_ context.Context,
	proposal *api.VersionedEPBSProposal,
	duty *beaconblockproposer.Duty,
) error {
	proposalSlot, err := proposal.Slot()
	if err != nil {
		return errors.Wrap(err, "failed to obtain ePBS proposal slot")
	}
	if proposalSlot != duty.Slot() {
		return errors.New("ePBS proposal data for incorrect slot")
	}
	proposalProposerIndex, err := proposal.ProposerIndex()
	if err != nil {
		return errors.Wrap(err, "failed to obtain ePBS proposal proposer index")
	}
	if proposalProposerIndex != duty.ValidatorIndex() {
		return errors.New("ePBS proposal data for incorrect proposer index")
	}

	return nil
}

// skipcq: GO-R1005
// Complexity is due to handling all Ethereum protocol versions.
// Each version requires specific signing logic for blinded/unblinded proposals.
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
	case spec.DataVersionElectra:
		if proposal.Blinded {
			signedProposal.ElectraBlinded = &apiv1electra.SignedBlindedBeaconBlock{
				Message:   proposal.ElectraBlinded,
				Signature: sig,
			}
		} else {
			signedProposal.Electra = &apiv1electra.SignedBlockContents{
				SignedBlock: &electra.SignedBeaconBlock{
					Message:   proposal.Electra.Block,
					Signature: sig,
				},
				KZGProofs: proposal.Electra.KZGProofs,
				Blobs:     proposal.Electra.Blobs,
			}
		}
	case spec.DataVersionFulu:
		if proposal.Blinded {
			signedProposal.FuluBlinded = &apiv1electra.SignedBlindedBeaconBlock{
				Message:   proposal.FuluBlinded,
				Signature: sig,
			}
		} else {
			signedProposal.Fulu = &apiv1fulu.SignedBlockContents{
				SignedBlock: &electra.SignedBeaconBlock{
					Message:   proposal.Fulu.Block,
					Signature: sig,
				},
				KZGProofs: proposal.Fulu.KZGProofs,
				Blobs:     proposal.Fulu.Blobs,
			}
		}
	default:
		return nil, errors.New("unhandled proposal version")
	}

	return signedProposal, nil
}

func (s *Service) signEPBSProposalData(ctx context.Context,
	proposal *api.VersionedEPBSProposal,
	duty *beaconblockproposer.Duty,
	bodyRoot phase0.Root,
) (
	*api.VersionedSignedProposal,
	error,
) {
	if proposal.Version != spec.DataVersionGloas {
		return nil, errors.New("unhandled ePBS proposal version")
	}

	parentRoot, err := proposal.ParentRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain parent root of ePBS block proposal")
	}

	stateRoot, err := proposal.StateRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain state root of ePBS block proposal")
	}

	sig, err := s.beaconBlockSigner.SignBeaconBlockProposal(ctx,
		duty.Account(),
		duty.Slot(),
		duty.ValidatorIndex(),
		parentRoot,
		stateRoot,
		bodyRoot)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign ePBS beacon block proposal")
	}

	block := proposal.Gloas
	if proposal.ExecutionPayloadIncluded {
		block = proposal.GloasContents.Block
	}

	return &api.VersionedSignedProposal{
		Version:        proposal.Version,
		ExecutionValue: proposal.ExecutionValue,
		ConsensusValue: proposal.ConsensusValue,
		Gloas: &gloas.SignedBeaconBlock{
			Message:   block,
			Signature: sig,
		},
	}, nil
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

// skipcq: GO-R1005
// Complexity is due to handling all Ethereum protocol versions.
// Each version requires specific logic to convert blinded to unblinded blocks.
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
						Electra:   proposal.ElectraBlinded,
						Fulu:      proposal.FuluBlinded,
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
		case spec.DataVersionElectra:
			proposal.ElectraBlinded = nil
			proposal.Electra = signedBlock.Electra
		case spec.DataVersionFulu:
			proposal.FuluBlinded = nil
			proposal.Fulu = signedBlock.Fulu
		default:
			return fmt.Errorf("unsupported version %v", proposal.Version)
		}
		proposal.Blinded = false

		return nil
	}
}
