// Copyright © 2020 Attestant Limited.
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
	"context"
	"fmt"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/graffitiprovider"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is a beacon block proposer.
type Service struct {
	monitor                    metrics.BeaconBlockProposalMonitor
	chainTimeService           chaintime.Service
	proposalProvider           eth2client.BeaconBlockProposalProvider
	validatingAccountsProvider accountmanager.ValidatingAccountsProvider
	graffitiProvider           graffitiprovider.Service
	beaconBlockSubmitter       submitter.BeaconBlockSubmitter
	randaoRevealSigner         signer.RANDAORevealSigner
	beaconBlockSigner          signer.BeaconBlockSigner
}

// module-wide log.
var log zerolog.Logger

// New creates a new beacon block proposer.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "beaconblockproposer").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		monitor:                    parameters.monitor,
		chainTimeService:           parameters.chainTimeService,
		proposalProvider:           parameters.proposalProvider,
		validatingAccountsProvider: parameters.validatingAccountsProvider,
		graffitiProvider:           parameters.graffitiProvider,
		beaconBlockSubmitter:       parameters.beaconBlockSubmitter,
		randaoRevealSigner:         parameters.randaoRevealSigner,
		beaconBlockSigner:          parameters.beaconBlockSigner,
	}

	return s, nil
}

// Prepare prepares for a beacon block proposal, carrying out activities that
// can be undertaken before the time the proposal is required.
func (s *Service) Prepare(ctx context.Context, data interface{}) error {
	started := time.Now()

	duty, ok := data.(*beaconblockproposer.Duty)
	if !ok {
		return errors.New("passed invalid data structure")
	}
	log := log.With().Uint64("proposing_slot", uint64(duty.Slot())).Uint64("validator_index", uint64(duty.ValidatorIndex())).Logger()
	log.Trace().Msg("Preparing")

	dutyEpoch := s.chainTimeService.SlotToEpoch(duty.Slot())
	// Fetch the validating account.
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx,
		dutyEpoch,
		[]spec.ValidatorIndex{duty.ValidatorIndex()},
	)
	if err != nil {
		return errors.Wrap(err, "failed to obtain proposing validator account")
	}
	if len(accounts) != 1 {
		return fmt.Errorf("unknown proposing validator account %d", duty.ValidatorIndex())
	}
	account := accounts[duty.ValidatorIndex()]
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained proposing account")
	duty.SetAccount(account)

	randaoReveal, err := s.randaoRevealSigner.SignRANDAOReveal(ctx, account, duty.Slot())
	if err != nil {
		return errors.Wrap(err, "failed to sign RANDAO reveal")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Signed RANDAO reveal")

	duty.SetRandaoReveal(randaoReveal)
	return nil
}

// Propose proposes a block.
func (s *Service) Propose(ctx context.Context, data interface{}) {
	started := time.Now()

	duty, ok := data.(*beaconblockproposer.Duty)
	if !ok {
		log.Error().Msg("Passed invalid data structure")
		s.monitor.BeaconBlockProposalCompleted(started, "failed")
		return
	}
	log := log.With().Uint64("proposing_slot", uint64(duty.Slot())).Uint64("validator_index", uint64(duty.ValidatorIndex())).Logger()
	log.Trace().Msg("Proposing")

	var graffiti []byte
	var err error
	if s.graffitiProvider != nil {
		graffiti, err = s.graffitiProvider.Graffiti(ctx, duty.Slot(), duty.ValidatorIndex())
		if err != nil {
			log.Warn().Err(err).Msg("Failed to obtain graffiti")
			graffiti = nil
		}
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained graffiti")

	proposal, err := s.proposalProvider.BeaconBlockProposal(ctx, duty.Slot(), duty.RANDAOReveal(), graffiti)
	if err != nil {
		log.Error().Err(err).Msg("Failed to obtain proposal data")
		s.monitor.BeaconBlockProposalCompleted(started, "failed")
		return
	}
	if proposal == nil {
		log.Error().Msg("Provider did not return beacon block proposal")
		s.monitor.BeaconBlockProposalCompleted(started, "failed")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained proposal")

	if proposal.Slot != duty.Slot() {
		log.Error().Uint64("proposal_slot", uint64(proposal.Slot)).Msg("Proposal data for incorrect slot; not proceeding")
		s.monitor.BeaconBlockProposalCompleted(started, "failed")
		return
	}

	bodyRoot, err := proposal.Body.HashTreeRoot()
	if err != nil {
		log.Error().Err(err).Msg("Failed to calculate hash tree root of block")
		s.monitor.BeaconBlockProposalCompleted(started, "failed")
		return
	}

	sig, err := s.beaconBlockSigner.SignBeaconBlockProposal(ctx,
		duty.Account(),
		proposal.Slot,
		duty.ValidatorIndex(),
		proposal.ParentRoot,
		proposal.StateRoot,
		bodyRoot)
	if err != nil {
		log.Error().Err(err).Msg("Failed to sign beacon block proposal")
		s.monitor.BeaconBlockProposalCompleted(started, "failed")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Signed proposal")

	signedBlock := &spec.SignedBeaconBlock{
		Message:   proposal,
		Signature: sig,
	}

	// Submit the block.
	if err := s.beaconBlockSubmitter.SubmitBeaconBlock(ctx, signedBlock); err != nil {
		log.Error().Err(err).Msg("Failed to submit beacon block proposal")
		s.monitor.BeaconBlockProposalCompleted(started, "failed")
		return
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted proposal")
	s.monitor.BeaconBlockProposalCompleted(started, "succeeded")
}
