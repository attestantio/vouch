// Copyright © 2025 Attestant Limited.
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
	"strings"
	"time"

	builderclient "github.com/attestantio/go-builder-client"
	builderapi "github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/semaphore"
)

// SubmitBlock submits a signed blinded block to a relay.
func (s *Service) SubmitBlock(ctx context.Context,
	block *api.VersionedSignedBlindedBeaconBlock,
) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "SubmitBlock")
	defer span.End()

	proposal := &api.VersionedSignedProposal{
		Version: block.Version,
		Blinded: true,
	}
	switch block.Version {
	case spec.DataVersionBellatrix:
		proposal.BellatrixBlinded = block.Bellatrix
	case spec.DataVersionCapella:
		proposal.CapellaBlinded = block.Capella
	case spec.DataVersionDeneb:
		proposal.DenebBlinded = block.Deneb
	case spec.DataVersionElectra:
		proposal.ElectraBlinded = block.Electra
	case spec.DataVersionFulu:
		proposal.FuluBlinded = block.Fulu
	default:
		return fmt.Errorf("unsupported block version %v", block.Version)
	}
	s.log.Trace().Msg("Submit block called")

	submitters, err := s.submittersForProposal(ctx, proposal)
	if err != nil {
		return err
	}
	if len(submitters) == 0 {
		return errors.New("no relays for submitting the proposal obtained")
	}

	if err := s.submitProposal(ctx, proposal, submitters); err != nil {
		return errors.Wrap(err, "failed to submit proposal")
	}

	return nil
}

func (s *Service) submittersForProposal(ctx context.Context,
	proposal *api.VersionedSignedProposal,
) (
	[]builderclient.SubmitBlindedProposalProvider,
	error,
) {
	// Obtain the validator's public key from its proposer index.
	proposerIndex, err := proposal.ProposerIndex()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain proposer index")
	}
	validatorsResponse, err := s.validatorsProvider.Validators(ctx, &api.ValidatorsOpts{
		State:   "head",
		Indices: []phase0.ValidatorIndex{proposerIndex},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain validator")
	}
	if len(validatorsResponse.Data) == 0 {
		return nil, errors.New("no validators returned")
	}
	validator, exists := validatorsResponse.Data[proposerIndex]
	if !exists {
		return nil, errors.New("required validator not returned")
	}
	pubkey, err := validator.PubKey(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain validator pubkey")
	}

	proposerConfig, err := s.ProposerConfig(ctx, nil, pubkey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain proposer configuration")
	}

	providers := make([]builderclient.SubmitBlindedProposalProvider, 0, len(proposerConfig.Relays))
	for _, relay := range proposerConfig.Relays {
		builderClient, err := util.FetchBuilderClient(ctx, "blockrelay", relay.Address, s.monitor, s.releaseVersion)
		if err != nil {
			// Error but continue.
			s.log.Error().Err(err).Msg("Failed to obtain builder client for proposal submission")
			continue
		}
		provider, isProvider := builderClient.(builderclient.SubmitBlindedProposalProvider)
		if !isProvider {
			// Error but continue.
			s.log.Error().Err(err).Msg("Builder client does not support submitting blinded proposals")
			continue
		}
		providers = append(providers, provider)
	}

	return providers, nil
}

func (s *Service) submitProposal(ctx context.Context,
	proposal *api.VersionedSignedProposal,
	providers []builderclient.SubmitBlindedProposalProvider,
) error {
	// We do not create a cancelable context, as if we do cancel the later-returning providers they will mark themselves
	// as failed even if they are just running a little slow, which isn't a useful thing to do.  Instead, we use a
	// semaphore to track if a signed block has been returned by any provider.
	sem := semaphore.NewWeighted(1)

	statusCh := make(chan byte, 1)
	for _, provider := range providers {
		go func(ctx context.Context, provider builderclient.SubmitBlindedProposalProvider, ch chan byte) {
			log := s.log.With().Str("provider", provider.Address()).Logger()
			log.Trace().Msg("Submitting block with provider")

			// As we cannot fall back we move to a retry system.
			retryInterval := 250 * time.Millisecond

			for retries := 3; retries > 0; retries-- {
				// Submit the signed blinded block.
				err := provider.SubmitBlindedProposal(ctx, &builderapi.SubmitBlindedProposalOpts{
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
					log.Debug().Err(err).Int("retries", retries).Msg("Failed to submit the block")
					if strings.Contains(err.Error(), "POST failed with status 404") {
						log.Debug().Msg("Responded with 404; not trying again as relay is not accepting the block")
						return
					}
					time.Sleep(retryInterval)
					continue
				}
				break
			}

			log.Trace().Msg("Block submitted")
			// Acquire the semaphore to confirm that a block has been received.
			// Use TryAcquire in case two providers receive the block at the same time.
			if sem.TryAcquire(1) {
				ch <- 0
			}
		}(ctx, provider, statusCh)
	}

	select {
	case <-ctx.Done():
		s.log.Warn().Msg("Failed to submit block")
		return errors.New("failed to submit block")
	case <-statusCh:
		return nil
	}
}
