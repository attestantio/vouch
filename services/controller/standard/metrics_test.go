// Copyright © 2026 Attestant Limited.
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

	eth2client "github.com/attestantio/go-eth2-client"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	mockattestationaggregator "github.com/attestantio/vouch/services/attestationaggregator/mock"
	mockattester "github.com/attestantio/vouch/services/attester/mock"
	mockbeaconblockproposer "github.com/attestantio/vouch/services/beaconblockproposer/mock"
	mockbeaconcommitteesubscriber "github.com/attestantio/vouch/services/beaconcommitteesubscriber/mock"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/attestantio/vouch/services/controller/standard"
	prometheusmetrics "github.com/attestantio/vouch/services/metrics/prometheus"
	alwaysmultiinstance "github.com/attestantio/vouch/services/multiinstance/always"
	mockproposalpreparer "github.com/attestantio/vouch/services/proposalpreparer/mock"
	mockscheduler "github.com/attestantio/vouch/services/scheduler/mock"
	mocksynccommitteeaggregator "github.com/attestantio/vouch/services/synccommitteeaggregator/mock"
	mocksynccommitteemessenger "github.com/attestantio/vouch/services/synccommitteemessenger/mock"
	mocksynccommitteesubscriber "github.com/attestantio/vouch/services/synccommitteesubscriber/mock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestHandleHeadEventBlockReceiptDelay(t *testing.T) {
	ctx := context.Background()

	zerolog.SetGlobalLevel(zerolog.Disabled)

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	monitor, err := prometheusmetrics.New(ctx,
		prometheusmetrics.WithLogLevel(zerolog.Disabled),
		prometheusmetrics.WithAddress("localhost:0"),
	)
	require.NoError(t, err)

	multiInstance, err := alwaysmultiinstance.New(ctx)
	require.NoError(t, err)

	tests := []struct {
		name             string
		eventsProvider   eth2client.EventsProvider
		expectedProvider string
	}{
		{
			name:             "WithAddressableProvider",
			eventsProvider:   mock.NewAddressableEventsProvider("http://lighthouse:5052"),
			expectedProvider: "http://lighthouse:5052",
		},
		{
			name:             "WithPlainProvider",
			eventsProvider:   mock.NewEventsProvider(),
			expectedProvider: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			svc, err := standard.New(ctx,
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithSpecProvider(specProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(mock.NewProposerDutiesProvider()),
				standard.WithAttesterDutiesProvider(mock.NewAttesterDutiesProvider()),
				standard.WithSyncCommitteeDutiesProvider(mock.NewSyncCommitteeDutiesProvider()),
				standard.WithEventsProvider(test.eventsProvider),
				standard.WithValidatingAccountsProvider(mockaccountmanager.NewValidatingAccountsProvider()),
				standard.WithProposalsPreparer(mockproposalpreparer.New()),
				standard.WithScheduler(mockscheduler.New()),
				standard.WithAttester(mockattester.New()),
				standard.WithSyncCommitteeMessenger(mocksynccommitteemessenger.New()),
				standard.WithSyncCommitteeAggregator(mocksynccommitteeaggregator.New()),
				standard.WithSyncCommitteeSubscriber(mocksynccommitteesubscriber.New()),
				standard.WithBeaconBlockProposer(mockbeaconblockproposer.New()),
				standard.WithBeaconCommitteeSubscriber(mockbeaconcommitteesubscriber.New()),
				standard.WithAttestationAggregator(mockattestationaggregator.New()),
				standard.WithAccountsRefresher(mockaccountmanager.NewRefresher()),
				standard.WithBlockToSlotSetter(mockcache.New(map[phase0.Root]phase0.Slot{}).(cache.BlockRootToSlotSetter)),
				standard.WithBeaconBlockHeadersProvider(mock.NewBeaconBlockHeadersProvider()),
				standard.WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				standard.WithMultiInstance(multiInstance),
			)
			require.NoError(t, err)

			data := &apiv1.HeadEvent{
				Slot: phase0.Slot(0),
			}
			svc.HandleHeadEvent(ctx, data)

			metrics, err := prometheus.DefaultGatherer.Gather()
			require.NoError(t, err)

			found := false
			for _, mf := range metrics {
				if mf.GetName() == "vouch_block_receipt_delay_seconds" {
					for _, m := range mf.GetMetric() {
						providerValue := ""
						for _, lp := range m.GetLabel() {
							if lp.GetName() == "provider" {
								providerValue = lp.GetValue()
							}
						}
						if providerValue == test.expectedProvider {
							found = true
						}
					}
				}
			}
			require.True(t, found, "expected to find vouch_block_receipt_delay_seconds metric with provider label %q", test.expectedProvider)
		})
	}
}
