// Copyright © 2022, 2024 Attestant Limited.
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
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// UpdatePreparations updates the preparations for validators on the beacon nodes.
func (s *Service) UpdatePreparations(ctx context.Context) error {
	ctx, span := otel.Tracer("attestantio.vouch.services.proposalpreparer.standard").Start(ctx, "UpdatePreparations")
	defer span.End()

	started := time.Now()

	epoch := s.chainTimeService.CurrentEpoch()

	// Fetch the validating accounts for the next epoch, to ensure that we capture any validators
	// that are going to start proposing soon.
	// Note that this will result in us not obtaining a validator that is on its last validating
	// epoch, however preparations linger for a couple of epochs after registration so this is safe.
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpoch(ctx, epoch+1)
	if err != nil {
		proposalPreparationCompleted(started, epoch, "failed")
		return errors.Wrap(err, "failed to obtain validating accounts")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained validating accounts")

	if len(accounts) == 0 {
		log.Trace().Msg("No validating accounts; not preparing")
		return nil
	}

	indices := make([]phase0.ValidatorIndex, len(accounts))
	i := 0
	for index := range accounts {
		indices[i] = index
		i++
	}

	proposalPreparations := make([]*apiv1.ProposalPreparation, 0, len(accounts))
	for index, account := range accounts {
		pubkey := util.ValidatorPubkey(account)
		proposerConfig, err := s.executionConfigProvider.ProposerConfig(ctx, account, pubkey)
		if err != nil {
			// Error but keep going, as we want to provide as many preparations as possible.
			log.Error().Str("pubkey", fmt.Sprintf("%#x", pubkey)).Err(err).Msg("Error obtaining propopser configuration")
			continue
		}
		if proposerConfig == nil {
			// Error but keep going, as we want to provide as many preparations as possible.
			log.Error().Str("pubkey", fmt.Sprintf("%#x", pubkey)).Msg("Obtained nil propopser configuration")
			continue
		}
		proposalPreparations = append(proposalPreparations, &apiv1.ProposalPreparation{
			ValidatorIndex: index,
			FeeRecipient:   proposerConfig.FeeRecipient,
		})
	}

	go s.updateProposalPreparations(ctx, started, epoch, proposalPreparations)

	return nil
}

func (s *Service) updateProposalPreparations(ctx context.Context,
	started time.Time,
	epoch phase0.Epoch,
	proposalPreparations []*apiv1.ProposalPreparation,
) {
	ctx, span := otel.Tracer("attestantio.vouch.services.proposalpreparer.standard").Start(ctx, "updateProposalPreparations", trace.WithAttributes(
		attribute.Int64("epoch", int64(epoch)),
	))
	defer span.End()

	failed := 0
	for _, proposalPreparationsSubmitter := range s.proposalPreparationsSubmitters {
		if err := proposalPreparationsSubmitter.SubmitProposalPreparations(ctx, proposalPreparations); err != nil {
			if errors.Is(err, eth2client.ErrNotActive) {
				// If the client isn't ready we don't count it as a failure.
				log.Debug().Str("client", proposalPreparationsSubmitter.(eth2client.Service).Address()).Msg("Client is no active; cannot update proposal preparations")
				continue
			}
			failed++
			log.Error().Str("client", proposalPreparationsSubmitter.(eth2client.Service).Address()).Err(err).Msg("Failed to update proposal preparations")
			// Do not exit here; we want to attempt all proposal preparations.
		}
	}

	if failed > 0 {
		proposalPreparationCompleted(started, epoch, "failed")
	} else {
		log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted proposal preparations")
		proposalPreparationCompleted(started, epoch, "succeeded")
	}
}
