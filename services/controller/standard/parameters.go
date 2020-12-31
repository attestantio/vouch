// Copyright © 2020 Attestant Limited.
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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/beaconcommitteesubscriber"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                   zerolog.Level
	monitor                    metrics.ControllerMonitor
	slotDurationProvider       eth2client.SlotDurationProvider
	slotsPerEpochProvider      eth2client.SlotsPerEpochProvider
	chainTimeService           chaintime.Service
	proposerDutiesProvider     eth2client.ProposerDutiesProvider
	attesterDutiesProvider     eth2client.AttesterDutiesProvider
	validatingAccountsProvider accountmanager.ValidatingAccountsProvider
	scheduler                  scheduler.Service
	eventsProvider             eth2client.EventsProvider
	attester                   attester.Service
	beaconBlockProposer        beaconblockproposer.Service
	attestationAggregator      attestationaggregator.Service
	beaconCommitteeSubscriber  beaconcommitteesubscriber.Service
	accountsRefresher          accountmanager.Refresher
	maxAttestationDelay        time.Duration
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

// WithMonitor sets the monitor for the module.
func WithMonitor(monitor metrics.ControllerMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithSlotDurationProvider sets the slot duration provider.
func WithSlotDurationProvider(provider eth2client.SlotDurationProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.slotDurationProvider = provider
	})
}

// WithSlotsPerEpochProvider sets the slots per epoch provider.
func WithSlotsPerEpochProvider(provider eth2client.SlotsPerEpochProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.slotsPerEpochProvider = provider
	})
}

// WithChainTimeService sets the chain time service.
func WithChainTimeService(service chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTimeService = service
	})
}

// WithProposerDutiesProvider sets the proposer duties provider.
func WithProposerDutiesProvider(provider eth2client.ProposerDutiesProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.proposerDutiesProvider = provider
	})
}

// WithAttesterDutiesProvider sets the attester duties provider.
func WithAttesterDutiesProvider(provider eth2client.AttesterDutiesProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attesterDutiesProvider = provider
	})
}

// WithEventsProvider sets the events provider.
func WithEventsProvider(provider eth2client.EventsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.eventsProvider = provider
	})
}

// WithValidatingAccountsProvider sets the validating accounts provider.
func WithValidatingAccountsProvider(provider accountmanager.ValidatingAccountsProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.validatingAccountsProvider = provider
	})
}

// WithScheduler sets the scheduler.
func WithScheduler(scheduler scheduler.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.scheduler = scheduler
	})
}

// WithAttester sets the attester.
func WithAttester(attester attester.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attester = attester
	})
}

// WithBeaconBlockProposer sets the beacon block propser.
func WithBeaconBlockProposer(proposer beaconblockproposer.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconBlockProposer = proposer
	})
}

// WithAttestationAggregator sets the attestation aggregator.
func WithAttestationAggregator(aggregator attestationaggregator.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.attestationAggregator = aggregator
	})
}

// WithBeaconCommitteeSubscriber sets the beacon committee subscriber.
func WithBeaconCommitteeSubscriber(subscriber beaconcommitteesubscriber.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconCommitteeSubscriber = subscriber
	})
}

// WithAccountsRefresher sets the account refresher.
func WithAccountsRefresher(refresher accountmanager.Refresher) Parameter {
	return parameterFunc(func(p *parameters) {
		p.accountsRefresher = refresher
	})
}

// WithMaxAttestationDelay sets the maximum delay before attesting.
func WithMaxAttestationDelay(delay time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.maxAttestationDelay = delay
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:            zerolog.GlobalLevel(),
		maxAttestationDelay: 4 * time.Second,
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.slotDurationProvider == nil {
		return nil, errors.New("no slot duration provider specified")
	}
	if parameters.slotsPerEpochProvider == nil {
		return nil, errors.New("no slots per epoch provider specified")
	}
	if parameters.chainTimeService == nil {
		return nil, errors.New("no chain time service specified")
	}
	if parameters.proposerDutiesProvider == nil {
		return nil, errors.New("no proposer duties provider specified")
	}
	if parameters.attesterDutiesProvider == nil {
		return nil, errors.New("no attester duties provider specified")
	}
	if parameters.eventsProvider == nil {
		return nil, errors.New("no events provider specified")
	}
	if parameters.validatingAccountsProvider == nil {
		return nil, errors.New("no validating accounts provider specified")
	}
	if parameters.scheduler == nil {
		return nil, errors.New("no scheduler service specified")
	}
	if parameters.attester == nil {
		return nil, errors.New("no attester specified")
	}
	if parameters.beaconBlockProposer == nil {
		return nil, errors.New("no beacon block proposer specified")
	}
	if parameters.attestationAggregator == nil {
		return nil, errors.New("no attestation aggregator specified")
	}
	if parameters.beaconCommitteeSubscriber == nil {
		return nil, errors.New("no beacon committee subscriber specified")
	}
	if parameters.accountsRefresher == nil {
		return nil, errors.New("no accounts refresher specified")
	}
	if parameters.maxAttestationDelay == 0 {
		return nil, errors.New("no maximum attestation delay specified")
	}

	return &parameters, nil
}
