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

package multinode

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the provider for a submitter.
type Service struct {
	log                                   zerolog.Logger
	clientMonitor                         metrics.ClientMonitor
	timeout                               time.Duration
	processConcurrency                    int64
	proposalSubmitters                    map[string]eth2client.ProposalSubmitter
	attestationsSubmitters                map[string]eth2client.AttestationsSubmitter
	aggregateAttestationsSubmitters       map[string]eth2client.AggregateAttestationsSubmitter
	proposalPreparationsSubmitters        map[string]eth2client.ProposalPreparationsSubmitter
	beaconCommitteeSubscriptionSubmitters map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter
	syncCommitteeMessagesSubmitter        map[string]eth2client.SyncCommitteeMessagesSubmitter
	syncCommitteeSubscriptionSubmitters   map[string]eth2client.SyncCommitteeSubscriptionsSubmitter
	syncCommitteeContributionsSubmitters  map[string]eth2client.SyncCommitteeContributionsSubmitter
}

// New creates a new multinode submitter.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("strategy", "submitter").Str("impl", "multinode").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		log:                                   log,
		clientMonitor:                         parameters.clientMonitor,
		timeout:                               parameters.timeout,
		processConcurrency:                    parameters.processConcurrency,
		proposalSubmitters:                    parameters.proposalSubmitters,
		attestationsSubmitters:                parameters.attestationsSubmitters,
		aggregateAttestationsSubmitters:       parameters.aggregateAttestationsSubmitters,
		proposalPreparationsSubmitters:        parameters.proposalPreparationsSubmitters,
		beaconCommitteeSubscriptionSubmitters: parameters.beaconCommitteeSubscriptionsSubmitters,
		syncCommitteeMessagesSubmitter:        parameters.syncCommitteeMessagesSubmitter,
		syncCommitteeSubscriptionSubmitters:   parameters.syncCommitteeSubscriptionsSubmitters,
		syncCommitteeContributionsSubmitters:  parameters.syncCommitteeContributionsSubmitters,
	}
	log.Trace().Int64("process_concurrency", s.processConcurrency).Msg("Set process concurrency")

	return s, nil
}
