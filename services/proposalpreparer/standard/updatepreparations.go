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

	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/blockbuilder"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// UpdatePreparations updates the preparations for validators on the beacon nodes.
func (s *Service) UpdatePreparations(ctx context.Context) error {
	started := time.Now()

	epoch := s.chainTimeService.CurrentEpoch()

	// ValidatingAccountsForEpoch obtains the validating accounts for a given epoch.
	accounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpoch(ctx, epoch)
	if err != nil {
		proposalPreparationCompleted(started, epoch, "failed")
		return errors.Wrap(err, "failed to obtain validating accounts")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained validating accounts")

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

	proposalPreparations := make([]*api.ProposalPreparation, len(feeRecipients))
	i = 0
	for index, feeRecipient := range feeRecipients {
		proposalPreparations[i] = &api.ProposalPreparation{
			ValidatorIndex: index,
			FeeRecipient:   feeRecipient,
		}
		i++
	}

	if err := s.proposalPreparationsSubmitter.SubmitProposalPreparations(ctx, proposalPreparations); err != nil {
		proposalPreparationCompleted(started, epoch, "failed")
		return errors.Wrap(err, "failed to update proposal preparations")
	}

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Submitted proposal preparations")
	proposalPreparationCompleted(started, epoch, "succeeded")

	// Also submit validator registrations if connected to builders.
	for _, validatorRegistrationsSubmitter := range s.validatorRegistrationsSubmitters {
		go func(ctx context.Context, submitter blockbuilder.ValidatorRegistrationsSubmitter, epoch phase0.Epoch, accounts map[phase0.ValidatorIndex]e2wtypes.Account, feeRecipients map[phase0.ValidatorIndex]bellatrix.ExecutionAddress) {
			if err := submitter.SubmitValidatorRegistrations(ctx, accounts, feeRecipients); err != nil {
				validatorRegistrationsCompleted("failed")
				log.Error().Err(err).Msg("Failed to update builder validator registrations")
				return
			}
			validatorRegistrationsCompleted("succeeded")
		}(ctx, validatorRegistrationsSubmitter, epoch, accounts, feeRecipients)
	}

	return nil
}
