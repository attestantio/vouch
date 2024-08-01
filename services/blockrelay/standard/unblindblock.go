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

package standard

import (
	"context"
	"encoding/json"
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

// UnblindBlock turns a blinded block into an unblinded block.
func (s *Service) UnblindBlock(ctx context.Context,
	block *api.VersionedSignedBlindedBeaconBlock,
) (
	*api.VersionedSignedProposal,
	error,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.blockrelay.standard").Start(ctx, "UnblindBlock")
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
	default:
		return nil, fmt.Errorf("unsupported block version %v", block.Version)
	}
	log.Trace().Msg("Unblind block called")

	unblinders, err := s.unblindersForProposal(ctx, proposal)
	if err != nil {
		return nil, err
	}
	if len(unblinders) == 0 {
		return nil, errors.New("no unblinders obtained")
	}

	if err := s.unblindProposal(ctx, proposal, unblinders); err != nil {
		return nil, errors.Wrap(err, "failed to unblind proposal")
	}

	return proposal, nil
}

func (s *Service) unblindersForProposal(ctx context.Context,
	proposal *api.VersionedSignedProposal,
) (
	[]builderclient.UnblindedProposalProvider,
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

	providers := make([]builderclient.UnblindedProposalProvider, 0, len(proposerConfig.Relays))
	for _, relay := range proposerConfig.Relays {
		builderClient, err := util.FetchBuilderClient(ctx, relay.Address, s.monitor, s.releaseVersion)
		if err != nil {
			// Error but continue.
			log.Error().Err(err).Msg("Failed to obtain builder client for unblinding")
			continue
		}
		provider, isProvider := builderClient.(builderclient.UnblindedProposalProvider)
		if !isProvider {
			// Error but continue.
			log.Error().Err(err).Msg("Builder client does not supply unblinding proposals")
			continue
		}
		providers = append(providers, provider)
	}

	return providers, nil
}

func (*Service) unblindProposal(ctx context.Context,
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
			log := log.With().Str("provider", provider.Address()).Logger()
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
			if signedProposalResponse == nil || signedProposalResponse.Data == nil {
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
		log.Warn().Msg("Failed to obtain unblinded block")
		return errors.New("failed to obtain unblinded block")
	case signedBlock := <-respCh:
		if e := log.Trace(); e.Enabled() {
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
