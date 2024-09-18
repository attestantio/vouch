// Copyright © 2020 - 2023 Attestant Limited.
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

// Package immediate is a submitter that immediately submits requests received.
package immediate

import (
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                              zerolog.Level
	proposalSubmitter                     eth2client.ProposalSubmitter
	attestationsSubmitter                 eth2client.AttestationsSubmitter
	beaconCommitteeSubscriptionsSubmitter eth2client.BeaconCommitteeSubscriptionsSubmitter
	aggregateAttestationsSubmitter        eth2client.AggregateAttestationsSubmitter
	proposalPreparationsSubmitter         eth2client.ProposalPreparationsSubmitter
	syncCommitteeMessagesSubmitter        eth2client.SyncCommitteeMessagesSubmitter
	syncCommitteeSubscriptionsSubmitter   eth2client.SyncCommitteeSubscriptionsSubmitter
	syncCommitteeContributionsSubmitter   eth2client.SyncCommitteeContributionsSubmitter
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(*parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(p *parameters) {
	f(p)
}

// WithLogLevel sets the log level for the module.
func WithLogLevel(logLevel zerolog.Level) Parameter {
	return parameterFunc(func(p *parameters) {
		p.logLevel = logLevel
	})
}

// WithProposalSubmitter sets the proposal submitter.
func WithProposalSubmitter(submitter eth2client.ProposalSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.proposalSubmitter = submitter
	})
}

// WithAttestationsSubmitter sets the attestation submitter.
func WithAttestationsSubmitter(submitter eth2client.AttestationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attestationsSubmitter = submitter
	})
}

// WithSyncCommitteeMessagesSubmitter sets the sync committee messages submitter.
func WithSyncCommitteeMessagesSubmitter(submitter eth2client.SyncCommitteeMessagesSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeMessagesSubmitter = submitter
	})
}

// WithSyncCommitteeSubscriptionsSubmitter sets the sync committee subscriptions submitter.
func WithSyncCommitteeSubscriptionsSubmitter(submitter eth2client.SyncCommitteeSubscriptionsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeSubscriptionsSubmitter = submitter
	})
}

// WithSyncCommitteeContributionsSubmitter sets the sync committee contributions submitter.
func WithSyncCommitteeContributionsSubmitter(submitter eth2client.SyncCommitteeContributionsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeContributionsSubmitter = submitter
	})
}

// WithBeaconCommitteeSubscriptionsSubmitter sets the attestation subnet subscriptions submitter.
func WithBeaconCommitteeSubscriptionsSubmitter(submitter eth2client.BeaconCommitteeSubscriptionsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconCommitteeSubscriptionsSubmitter = submitter
	})
}

// WithAggregateAttestationsSubmitter sets the aggregate attestation submitter.
func WithAggregateAttestationsSubmitter(submitter eth2client.AggregateAttestationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.aggregateAttestationsSubmitter = submitter
	})
}

// WithProposalPreparationsSubmitter sets the proposal preparations submitter.
func WithProposalPreparationsSubmitter(submitter eth2client.ProposalPreparationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.proposalPreparationsSubmitter = submitter
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.proposalSubmitter == nil {
		return nil, errors.New("no proposal submitter specified")
	}
	if parameters.attestationsSubmitter == nil {
		return nil, errors.New("no attestations submitter specified")
	}
	if parameters.syncCommitteeMessagesSubmitter == nil {
		return nil, errors.New("no sync committee messages submitter specified")
	}
	if parameters.syncCommitteeSubscriptionsSubmitter == nil {
		return nil, errors.New("no sync committee subscriptions submitter specified")
	}
	if parameters.syncCommitteeContributionsSubmitter == nil {
		return nil, errors.New("no sync committee contributions submitter specified")
	}
	if parameters.beaconCommitteeSubscriptionsSubmitter == nil {
		return nil, errors.New("no beacon committee subscriptions submitter specified")
	}
	if parameters.aggregateAttestationsSubmitter == nil {
		return nil, errors.New("no aggregate attestations submitter specified")
	}
	if parameters.proposalPreparationsSubmitter == nil {
		return nil, errors.New("no proposal preparations submitter specified")
	}

	return &parameters, nil
}
