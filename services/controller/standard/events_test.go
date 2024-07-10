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

package standard_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/vouch/services/synccommitteemessenger"
	"github.com/attestantio/vouch/testutil"
	"github.com/prysmaticlabs/go-bitfield"
	"testing"
	"time"

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
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mockproposalpreparer "github.com/attestantio/vouch/services/proposalpreparer/mock"
	mockscheduler "github.com/attestantio/vouch/services/scheduler/mock"
	mocksynccommitteeaggregator "github.com/attestantio/vouch/services/synccommitteeaggregator/mock"
	mocksynccommitteemessenger "github.com/attestantio/vouch/services/synccommitteemessenger/mock"
	mocksynccommitteesubscriber "github.com/attestantio/vouch/services/synccommitteesubscriber/mock"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestVerifySyncCommitteeEvents(t *testing.T) {
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

	happySignedBeaconBlockProvider := mock.NewSignedBeaconBlockProvider()
	unhappySignedBeaconBlockProvider := mock.NewErroringSignedBeaconBlockProvider()
	primedSignedBeaconBlockProvider := mock.NewPrimedSignedBeaconBlockProvider()

	mockBlockHeadersProvider := mock.NewBeaconBlockHeadersProvider()
	mockSyncCommitteeAggregator := mocksynccommitteeaggregator.New()
	proposerDutiesProvider := mock.NewProposerDutiesProvider()
	attesterDutiesProvider := mock.NewAttesterDutiesProvider()
	syncCommitteeDutiesProvider := mock.NewSyncCommitteeDutiesProvider()
	mockScheduler := mockscheduler.New()
	mockAttester := mockattester.New()
	mockSyncCommitteeMessenger := mocksynccommitteemessenger.New()
	mockSyncCommitteeSubscriber := mocksynccommitteesubscriber.New()
	mockAttestationAggregator := mockattestationaggregator.New()
	mockValidatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	mockProposalsPreparer := mockproposalpreparer.New()
	mockAccountsRefresher := mockaccountmanager.NewRefresher()
	mockBeaconBlockProposer := mockbeaconblockproposer.New()
	mockEventsProvider := mock.NewEventsProvider()
	mockBeaconCommitteeSubscriber := mockbeaconcommitteesubscriber.New()
	mockBlockToSlotSetter := mockcache.New(map[phase0.Root]phase0.Slot{}).(cache.BlockRootToSlotSetter)

	params := []standard.Parameter{
		standard.WithLogLevel(zerolog.TraceLevel),
		standard.WithMonitor(nullmetrics.New(ctx)),
		standard.WithSpecProvider(specProvider),
		standard.WithChainTimeService(chainTime),
		standard.WithProposerDutiesProvider(proposerDutiesProvider),
		standard.WithAttesterDutiesProvider(attesterDutiesProvider),
		standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
		standard.WithEventsProvider(mockEventsProvider),
		standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
		standard.WithProposalsPreparer(mockProposalsPreparer),
		standard.WithScheduler(mockScheduler),
		standard.WithAttester(mockAttester),
		standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
		standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
		standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
		standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
		standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
		standard.WithAttestationAggregator(mockAttestationAggregator),
		standard.WithAccountsRefresher(mockAccountsRefresher),
		standard.WithBlockToSlotSetter(mockBlockToSlotSetter),
		standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
	}

	epoch := phase0.Epoch(100)
	slot := phase0.Slot(epoch * 32)
	root := testutil.HexToRoot("0x0606060606060606060606060606060606060606060606060606060606060606")
	mismatchingRoot := testutil.HexToRoot("0x0909090909090909090909090909090909090909090909090909090909090909")
	messageIndices := testutil.CreateMessageIndices()
	duty := synccommitteemessenger.NewDuty(slot, messageIndices)

	validatorIndices := make([]phase0.ValidatorIndex, 10)
	for validatorIndex := range 10 {
		validatorIndices[validatorIndex] = phase0.ValidatorIndex(validatorIndex)
	}
	accounts, err := testutil.CreateTestWalletAndAccounts(validatorIndices, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)

	bitvector512 := bitfield.NewBitvector512()
	for validIndex, testAccount := range accounts {
		duty.SetAccount(validIndex, testAccount)
		mockValidatingAccountsProvider.AddAccount(validIndex, testAccount)
		bitvector512.SetBitAt(uint64(validIndex), true)
	}

	responseBlock := api.Response[*spec.VersionedSignedBeaconBlock]{
		Data: &spec.VersionedSignedBeaconBlock{
			Version: spec.DataVersionAltair,
			Altair: &altair.SignedBeaconBlock{
				Message: &altair.BeaconBlock{
					Slot:       slot,
					ParentRoot: root,
					Body: &altair.BeaconBlockBody{
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits:      bitvector512,
							SyncCommitteeSignature: testutil.HexToSignature("0x080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808"),
						},
					},
				},
			},
		},
	}

	primedSignedBeaconBlockProvider.PrimeResponse(&responseBlock)

	tests := []struct {
		name                string
		params              []standard.Parameter
		err                 string
		logEntries          []string
		testSpecificPriming func(service *mocksynccommitteemessenger.Service)
	}{
		{
			name:   "SuccessfullyVerifiesParticipation",
			params: append(params, standard.WithSignedBeaconBlockProvider(primedSignedBeaconBlockProvider)),
			logEntries: []string{
				"Received head event",
			},
			testSpecificPriming: func(service *mocksynccommitteemessenger.Service) {
				service.PrimeLastReported(slot, synccommitteemessenger.RootReported{Root: root, ValidatorIndices: validatorIndices})
			},
		},
		{
			name:   "FailedToGetSignedBeaconBlock",
			params: append(params, standard.WithSignedBeaconBlockProvider(unhappySignedBeaconBlockProvider)),
			logEntries: []string{
				"Received head event",
				fmt.Sprintf("failed to retrieve block: %s for slot: %d with err: %v", root.String(), slot, errors.New("error")),
			},
			testSpecificPriming: func(service *mocksynccommitteemessenger.Service) {
				service.PrimeLastReported(slot, synccommitteemessenger.RootReported{Root: root, ValidatorIndices: validatorIndices})
			},
		},
		{
			name:   "FailedToGetReportedCommitteeMessage",
			params: append(params, standard.WithSignedBeaconBlockProvider(happySignedBeaconBlockProvider)),
			logEntries: []string{
				"Received head event",
				fmt.Sprintf("no reported sync committee message data for slot: %d, skipping validation", slot),
			},
			testSpecificPriming: func(service *mocksynccommitteemessenger.Service) {},
		},
		{
			name:   "MismatchRootBetweenBlockAndReported",
			params: append(params, standard.WithSignedBeaconBlockProvider(happySignedBeaconBlockProvider)),
			logEntries: []string{
				"Received head event",
				fmt.Sprintf("mismatch in block root for slot: %d. Reported: %s and observed: %s", slot, mismatchingRoot.String(), root.String()),
			},
			testSpecificPriming: func(service *mocksynccommitteemessenger.Service) {
				service.PrimeLastReported(slot, synccommitteemessenger.RootReported{Root: mismatchingRoot, ValidatorIndices: validatorIndices})
			},
		},
		{
			name:   "FailedToGetSyncAggregate",
			params: append(params, standard.WithSignedBeaconBlockProvider(happySignedBeaconBlockProvider)),
			logEntries: []string{
				"Received head event",
				fmt.Sprintf("failed to get sync aggregate for block: %s for slot: %d with err: %v", root.String(), slot, errors.New("phase0 block does not have sync aggregate")),
			},
			testSpecificPriming: func(service *mocksynccommitteemessenger.Service) {
				service.PrimeLastReported(slot, synccommitteemessenger.RootReported{Root: root, ValidatorIndices: validatorIndices})
			},
		},
		{
			name:   "ValidatorMissingFromSyncAggregate",
			params: append(params, standard.WithSignedBeaconBlockProvider(primedSignedBeaconBlockProvider)),
			logEntries: []string{
				"Received head event",
				fmt.Sprintf("validator with index: %d not included in sync committee aggregate bits", 11),
			},
			testSpecificPriming: func(service *mocksynccommitteemessenger.Service) {
				service.PrimeLastReported(slot, synccommitteemessenger.RootReported{Root: root, ValidatorIndices: append(validatorIndices, 11)})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			standardService, err := standard.New(ctx, test.params...)
			require.NoError(t, err)

			// Reset and prime the mock for each test
			mockSyncCommitteeMessenger.ResetMock()
			test.testSpecificPriming(mockSyncCommitteeMessenger)

			data := &apiv1.HeadEvent{
				Slot:  slot,
				Block: root,
			}
			standardService.VerifySyncCommitteeMessages(ctx, data)
			foundLogEntries := 0
			for _, logEntry := range test.logEntries {
				logMap := map[string]any{"slot": uint64(3200)}
				logMap["message"] = logEntry
				require.True(t, capture.HasLog(logMap))
				foundLogEntries++
			}
			require.Equal(t, len(test.logEntries), foundLogEntries, "unexpected number of log entries")
		})
	}
}
