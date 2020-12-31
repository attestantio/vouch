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

package standard_test

import (
	"context"
	"testing"
	"time"

	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	mockattestationaggregator "github.com/attestantio/vouch/services/attestationaggregator/mock"
	mockattester "github.com/attestantio/vouch/services/attester/mock"
	mockbeaconblockproposer "github.com/attestantio/vouch/services/beaconblockproposer/mock"
	mockbeaconcommitteesubscriber "github.com/attestantio/vouch/services/beaconcommitteesubscriber/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/attestantio/vouch/services/controller/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mockscheduler "github.com/attestantio/vouch/services/scheduler/mock"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	slotDuration := 12 * time.Second
	slotsPerEpoch := uint64(32)
	mockGenesisTimeProvider := mock.NewGenesisTimeProvider(genesisTime)
	mockSlotDurationProvider := mock.NewSlotDurationProvider(slotDuration)
	mockSlotsPerEpochProvider := mock.NewSlotsPerEpochProvider(slotsPerEpoch)

	proposerDutiesProvider := mock.NewProposerDutiesProvider()
	attesterDutiesProvider := mock.NewAttesterDutiesProvider()
	mockScheduler := mockscheduler.New()
	mockAttester := mockattester.New()
	mockAttestationAggregator := mockattestationaggregator.New()
	mockValidatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	mockAccountsRefresher := mockaccountmanager.NewRefresher()
	mockBeaconBlockProposer := mockbeaconblockproposer.New()
	mockEventsProvider := mock.NewEventsProvider()
	mockBeaconCommitteeSubscriber := mockbeaconcommitteesubscriber.New()

	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithGenesisTimeProvider(mockGenesisTimeProvider),
		standardchaintime.WithSlotDurationProvider(mockSlotDurationProvider),
		standardchaintime.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		params   []standard.Parameter
		err      string
		logEntry string
	}{
		{
			name: "MonitorNil",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "SlotDurationProviderNotSpecified",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no slot duration provider specified",
		},
		{
			name: "SlotDurationProviderErrors",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mock.NewErroringSlotDurationProvider()),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "failed to obtain slot duration: mock",
		},
		{
			name: "SlotsPerEpochProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no slots per epoch provider specified",
		},
		{
			name: "SlotsPerEpochProviderErrors",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mock.NewErroringSlotsPerEpochProvider()),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "failed to obtain slots per epoch: error",
		},
		{
			name: "ChainTimeServiceMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "ProposerDutiesProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no proposer duties provider specified",
		},
		{
			name: "AttesterDutiesProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no attester duties provider specified",
		},
		{
			name: "EventsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no events provider specified",
		},
		{
			name: "ValidatingAccountsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no validating accounts provider specified",
		},
		{
			name: "SchedulerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no scheduler service specified",
		},
		{
			name: "AttesterMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no attester specified",
		},
		{
			name: "BeaconBlockProposerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no beacon block proposer specified",
		},
		{
			name: "BeaconCommitteeSubscriberMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no beacon committee subscriber specified",
		},
		{
			name: "AttestationAggregatorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no attestation aggregator specified",
		},
		{
			name: "AccountsRefresherMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
			err: "problem with parameters: no accounts refresher specified",
		},
		{
			name: "MaxAttestationDelayZero",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(0),
			},
			err: "problem with parameters: no maximum attestation delay specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSlotDurationProvider(mockSlotDurationProvider),
				standard.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithMaxAttestationDelay(4 * time.Second),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			_, err := standard.New(ctx, test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				if test.logEntry != "" {
					capture.AssertHasEntry(t, test.logEntry)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
