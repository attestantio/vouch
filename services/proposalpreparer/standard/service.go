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

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/blockrelay"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/feerecipientprovider"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is a proposal preparer.
type Service struct {
	chainTimeService                 chaintime.Service
	validatingAccountsProvider       accountmanager.ValidatingAccountsProvider
	feeRecipientProvider             feerecipientprovider.Service
	proposalPreparationsSubmitter    eth2client.ProposalPreparationsSubmitter
	validatorRegistrationsSubmitters []blockrelay.ValidatorRegistrationsSubmitter
}

// module-wide log.
var log zerolog.Logger

// New creates a new proposal preparer.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "proposalpreparer").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}

	s := &Service{
		chainTimeService:                 parameters.chainTimeService,
		validatingAccountsProvider:       parameters.validatingAccountsProvider,
		feeRecipientProvider:             parameters.feeRecipientProvider,
		proposalPreparationsSubmitter:    parameters.proposalPreparationsSubmitter,
		validatorRegistrationsSubmitters: parameters.validatorRegistrationsSubmitters,
	}

	return s, nil
}
