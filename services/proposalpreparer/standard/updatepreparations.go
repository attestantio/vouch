// Copyright © 2022 Attestant Limited.
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
	"time"

	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// UpdatePreparations updates the preparations for validators on the beacon nodes.
func (s *Service) UpdatePreparations(ctx context.Context) error {
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

	feeRecipients, err := s.feeRecipientProvider.FeeRecipients(ctx, indices)
	if err != nil {
		return errors.Wrap(err, "failed to obtain fee recipients")
	}

	proposalPreparations := make([]*apiv1.ProposalPreparation, len(feeRecipients))
	i = 0
	for index, feeRecipient := range feeRecipients {
		proposalPreparations[i] = &apiv1.ProposalPreparation{
			ValidatorIndex: index,
			FeeRecipient:   feeRecipient,
		}
		i++
	}

	go s.updateProposalPreparations(ctx, started, epoch, proposalPreparations)
	go s.updateValidatorRegistrations(ctx, started, accounts)

	return nil
}

func (s *Service) updateValidatorRegistrations(ctx context.Context,
	started time.Time,
	accounts map[phase0.ValidatorIndex]e2wtypes.Account,
) {
	if s.validatorRegistrationsSubmitter == nil {
		return
	}

	if err := s.validatorRegistrationsSubmitter.SubmitValidatorRegistrations(ctx, accounts); err != nil {
		validatorRegistrationsCompleted("failed")
		log.Error().Err(err).Msg("Failed to update validator registrations")
		return
	}
	validatorRegistrationsCompleted("succeeded")
	log.Trace().Dur("elapsed", time.Since(started)).Msg("updated validator registrations")
}

func (s *Service) updateProposalPreparations(ctx context.Context,
	started time.Time,
	epoch phase0.Epoch,
	proposalPreparations []*apiv1.ProposalPreparation,
) {
	if err := s.proposalPreparationsSubmitter.SubmitProposalPreparations(ctx, proposalPreparations); err != nil {
		proposalPreparationCompleted(started, epoch, "failed")
		log.Error().Err(err).Msg("Failed to update proposal preparations")
		return
	}

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted proposal preparations")
	proposalPreparationCompleted(started, epoch, "succeeded")
}
