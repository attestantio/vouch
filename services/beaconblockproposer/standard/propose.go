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
	"time"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/pkg/errors"
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

// proposeBlock proposes a full block.
func (s *Service) proposeBlock(ctx context.Context,
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
