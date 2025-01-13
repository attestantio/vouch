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

// Package multinode is a strategy that obtains beacon block proposals from multiple
// nodes and selects the best one based on its attestation load.
package multinode

import (
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                               zerolog.Level
	timeout                                time.Duration
	clientMonitor                          metrics.ClientMonitor
	processConcurrency                     int64
	proposalSubmitters                     map[string]eth2client.ProposalSubmitter
	attestationsSubmitters                 map[string]eth2client.AttestationsSubmitter
	versionedAttestationsSubmitters        map[string]eth2client.VersionedAttestationsSubmitter
	aggregateAttestationsSubmitters        map[string]eth2client.AggregateAttestationsSubmitter
	proposalPreparationsSubmitters         map[string]eth2client.ProposalPreparationsSubmitter
	beaconCommitteeSubscriptionsSubmitters map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter
	syncCommitteeMessagesSubmitter         map[string]eth2client.SyncCommitteeMessagesSubmitter
	syncCommitteeSubscriptionsSubmitters   map[string]eth2client.SyncCommitteeSubscriptionsSubmitter
	syncCommitteeContributionsSubmitters   map[string]eth2client.SyncCommitteeContributionsSubmitter
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(p *parameters)
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

// WithTimeout sets the timeout for calls made by the module.
func WithTimeout(timeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.timeout = timeout
	})
}

// WithClientMonitor sets the client monitor.
func WithClientMonitor(clientMonitor metrics.ClientMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.clientMonitor = clientMonitor
	})
}

// WithProcessConcurrency sets the concurrency for the service.
func WithProcessConcurrency(concurrency int64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.processConcurrency = concurrency
	})
}

// WithProposalSubmitters sets the proposal submitters.
func WithProposalSubmitters(submitters map[string]eth2client.ProposalSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.proposalSubmitters = submitters
	})
}

// WithAttestationsSubmitters sets the attestation submitters.
func WithAttestationsSubmitters(submitters map[string]eth2client.AttestationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attestationsSubmitters = submitters
	})
}

// WithVersionedAttestationsSubmitters sets the versioned attestation submitters.
func WithVersionedAttestationsSubmitters(submitters map[string]eth2client.VersionedAttestationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.versionedAttestationsSubmitters = submitters
	})
}

// WithAggregateAttestationsSubmitters sets the aggregate attestation submitters.
func WithAggregateAttestationsSubmitters(submitters map[string]eth2client.AggregateAttestationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.aggregateAttestationsSubmitters = submitters
	})
}

// WithProposalPreparationsSubmitters sets the proposal preparation submitters.
func WithProposalPreparationsSubmitters(submitters map[string]eth2client.ProposalPreparationsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.proposalPreparationsSubmitters = submitters
	})
}

// WithBeaconCommitteeSubscriptionsSubmitters sets the attestation submitters.
func WithBeaconCommitteeSubscriptionsSubmitters(submitters map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconCommitteeSubscriptionsSubmitters = submitters
	})
}

// WithSyncCommitteeMessagesSubmitters sets the sync committee messages submitters.
func WithSyncCommitteeMessagesSubmitters(submitters map[string]eth2client.SyncCommitteeMessagesSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeMessagesSubmitter = submitters
	})
}

// WithSyncCommitteeSubscriptionsSubmitters sets the sync committee subscriptions submitters.
func WithSyncCommitteeSubscriptionsSubmitters(submitters map[string]eth2client.SyncCommitteeSubscriptionsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeSubscriptionsSubmitters = submitters
	})
}

// WithSyncCommitteeContributionsSubmitters sets the sync committee contributions submitters.
func WithSyncCommitteeContributionsSubmitters(submitters map[string]eth2client.SyncCommitteeContributionsSubmitter) Parameter {
	return parameterFunc(func(p *parameters) {
		p.syncCommitteeContributionsSubmitters = submitters
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:      zerolog.GlobalLevel(),
		clientMonitor: nullmetrics.New(),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.timeout == 0 {
		return nil, errors.New("no timeout specified")
	}
	if parameters.clientMonitor == nil {
		return nil, errors.New("no client monitor specified")
	}
	if parameters.processConcurrency == 0 {
		return nil, errors.New("no process concurrency specified")
	}
	if len(parameters.proposalSubmitters) == 0 {
		return nil, errors.New("no proposal submitters specified")
	}
	if len(parameters.attestationsSubmitters) == 0 {
		return nil, errors.New("no attestations submitters specified")
	}
	if len(parameters.versionedAttestationsSubmitters) == 0 {
		return nil, errors.New("no versioned attestations submitters specified")
	}
	if len(parameters.aggregateAttestationsSubmitters) == 0 {
		return nil, errors.New("no aggregate attestations submitters specified")
	}
	if len(parameters.proposalPreparationsSubmitters) == 0 {
		return nil, errors.New("no proposal preparations submitters specified")
	}
	if len(parameters.beaconCommitteeSubscriptionsSubmitters) == 0 {
		return nil, errors.New("no beacon committee subscription submitters specified")
	}
	if len(parameters.syncCommitteeMessagesSubmitter) == 0 {
		return nil, errors.New("no sync committee messages submitters specified")
	}
	if len(parameters.syncCommitteeSubscriptionsSubmitters) == 0 {
		return nil, errors.New("no sync committee subscriptions submitters specified")
	}
	if len(parameters.syncCommitteeContributionsSubmitters) == 0 {
		return nil, errors.New("no sync committee contributions submitters specified")
	}

	return &parameters, nil
}
