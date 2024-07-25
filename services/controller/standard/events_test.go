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
	currentSlot := phase0.Slot(epoch * 32)
	previousSlot := currentSlot - 1
	root := testutil.HexToRoot("0x0606060606060606060606060606060606060606060606060606060606060606")
	mismatchingRoot := testutil.HexToRoot("0x0909090909090909090909090909090909090909090909090909090909090909")
	validatorIndexToCommitteeIndices := testutil.CreateValidatorIndexToCommitteeIndicesTestData()
	duty := synccommitteemessenger.NewDuty(previousSlot, validatorIndexToCommitteeIndices)

	// Extract validator indices to array and create bitvector to mock SyncAggregate data.
	validatorIndices := make([]phase0.ValidatorIndex, len(validatorIndexToCommitteeIndices))
	bitvector512 := bitfield.NewBitvector512()
	for validatorIndex, committeeIndices := range validatorIndexToCommitteeIndices {
		validatorIndices[validatorIndex] = validatorIndex
		for _, committeeIndex := range committeeIndices {
			bitvector512.SetBitAt(uint64(committeeIndex), true)
		}
	}

	accounts, err := testutil.CreateTestWalletAndAccounts(validatorIndices, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)

	for validIndex, testAccount := range accounts {
		duty.SetAccount(validIndex, testAccount)
		mockValidatingAccountsProvider.AddAccount(validIndex, testAccount)
	}

	responseBlock := api.Response[*spec.VersionedSignedBeaconBlock]{
		Data: &spec.VersionedSignedBeaconBlock{
			Version: spec.DataVersionAltair,
			Altair: &altair.SignedBeaconBlock{
				Message: &altair.BeaconBlock{
					Slot:       currentSlot,
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
				service.PrimeLastReported(previousSlot, synccommitteemessenger.SlotData{Root: root, ValidatorToCommitteeIndex: validatorIndexToCommitteeIndices})
			},
		},
		{
			name:   "FailedToGetSignedBeaconBlock",
			params: append(params, standard.WithSignedBeaconBlockProvider(unhappySignedBeaconBlockProvider)),
			logEntries: []string{
				"Received head event",
				"Failed to retrieve head block for sync committee verification",
			},
			testSpecificPriming: func(service *mocksynccommitteemessenger.Service) {
				service.PrimeLastReported(previousSlot, synccommitteemessenger.SlotData{Root: root, ValidatorToCommitteeIndex: validatorIndexToCommitteeIndices})
			},
		},
		{
			name:   "FailedToGetReportedCommitteeMessage",
			params: append(params, standard.WithSignedBeaconBlockProvider(happySignedBeaconBlockProvider)),
			logEntries: []string{
				"Received head event",
				"No reported sync committee message data for slot; skipping verification",
			},
			testSpecificPriming: func(_ *mocksynccommitteemessenger.Service) {},
		},
		{
			name:   "MismatchRootBetweenBlockAndReported",
			params: append(params, standard.WithSignedBeaconBlockProvider(happySignedBeaconBlockProvider)),
			logEntries: []string{
				"Received head event",
				"Parent root does not equal sync committee root broadcast",
			},
			testSpecificPriming: func(service *mocksynccommitteemessenger.Service) {
				service.PrimeLastReported(previousSlot, synccommitteemessenger.SlotData{Root: mismatchingRoot, ValidatorToCommitteeIndex: validatorIndexToCommitteeIndices})
			},
		},
		{
			name:   "FailedToGetSyncAggregate",
			params: append(params, standard.WithSignedBeaconBlockProvider(primedSignedBeaconBlockProvider)),
			logEntries: []string{
				"Received head event",
				"Failed to get sync aggregate retrieved from head block",
			},
			testSpecificPriming: func(service *mocksynccommitteemessenger.Service) {
				missingAggregateResponseBlock := api.Response[*spec.VersionedSignedBeaconBlock]{
					Data: &spec.VersionedSignedBeaconBlock{
						Version: spec.DataVersionAltair,
						Altair: &altair.SignedBeaconBlock{
							Message: &altair.BeaconBlock{
								Slot:       currentSlot,
								ParentRoot: root,
								Body:       nil,
							},
						},
					},
				}
				primedSignedBeaconBlockProvider.PrimeResponse(&missingAggregateResponseBlock)
				service.PrimeLastReported(previousSlot, synccommitteemessenger.SlotData{Root: root, ValidatorToCommitteeIndex: validatorIndexToCommitteeIndices})
			},
		},
		{
			name:   "ValidatorMissingFromSyncAggregate",
			params: append(params, standard.WithSignedBeaconBlockProvider(primedSignedBeaconBlockProvider)),
			logEntries: []string{
				"Received head event",
				"Validator not included in SyncAggregate SyncCommitteeBits",
			},
			testSpecificPriming: func(service *mocksynccommitteemessenger.Service) {
				validatorIndexToCommitteeWithExtraValidator := validatorIndexToCommitteeIndices
				validatorIndexToCommitteeWithExtraValidator[11] = []phase0.CommitteeIndex{200}
				service.PrimeLastReported(previousSlot, synccommitteemessenger.SlotData{Root: root, ValidatorToCommitteeIndex: validatorIndexToCommitteeWithExtraValidator})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			standardService, err := standard.New(ctx, test.params...)
			require.NoError(t, err)

			// Reset and prime the mock for each test.
			mockSyncCommitteeMessenger.ResetMock()
			// Prime the block provider before each test. The test specific priming may override this.
			primedSignedBeaconBlockProvider.PrimeResponse(&responseBlock)
			test.testSpecificPriming(mockSyncCommitteeMessenger)

			data := &apiv1.HeadEvent{
				Slot:  currentSlot,
				Block: root,
			}
			standardService.VerifySyncCommitteeMessages(ctx, data)
			foundLogEntries := 0
			for _, logEntry := range test.logEntries {
				// Filter on slot field to ignore output from other controller functions.
				logMap := map[string]any{"current_slot": uint64(currentSlot)}
				logMap["message"] = logEntry
				require.True(t, capture.HasLog(logMap), fmt.Sprintf("failed to find message %q in output", logEntry))
				foundLogEntries++
			}
			require.Equal(t, len(test.logEntries), foundLogEntries, "Unexpected number of log entries")
		})
	}
}
