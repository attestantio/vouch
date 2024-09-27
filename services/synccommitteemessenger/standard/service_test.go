// Copyright © 2024 Attestant Limited.
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

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/synccommitteemessenger"
	"github.com/attestantio/vouch/testutil"

	mocketh2client "github.com/attestantio/go-eth2-client/mock"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	nullsubmitter "github.com/attestantio/vouch/services/submitter/null"
	mocksynccommitteeaggregator "github.com/attestantio/vouch/services/synccommitteeaggregator/mock"
	"github.com/attestantio/vouch/services/synccommitteemessenger/standard"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	mockSyncCommitteeAggregator := mocksynccommitteeaggregator.New()
	mockSigner := mocksigner.New()
	nullSubmitter, err := nullsubmitter.New(ctx)
	require.NoError(t, err)
	mockETH2Client, err := mocketh2client.New(ctx)
	require.NoError(t, err)
	mockValidatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()

	tests := []struct {
		name     string
		params   []standard.Parameter
		err      string
		logEntry string
	}{
		{
			name: "ProcessConcurrencyBad",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(-1),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no process concurrency specified",
		},
		{
			name: "MonitorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nil),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ChainTimeMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "SyncCommitteeAggregatorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no sync committee aggregator specified",
		},
		{
			name: "SpecProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no spec provider specified",
		},
		{
			name: "BeaconBlockRootProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no beacon block root provider specified",
		},
		{
			name: "SyncCommitteeMessagesSubmitterMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no sync committee messages submitter specified",
		},
		{
			name: "ValidatingAccountsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no validating accounts provider specified",
		},
		{
			name: "SyncCommitteeRootSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no sync committee root signer specified",
		},
		{
			name: "SyncCommitteeSelectionSignerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
			err: "problem with parameters: no sync committee selection signer specified",
		},
		{
			name: "SynccommitteeSubscriptionsSubmitterMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
			},
			err: "problem with parameters: no sync committee subscriptions submitter specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
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

func TestServiceMessage(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	nullSubmitter, err := nullsubmitter.New(ctx)
	require.NoError(t, err)
	mockETH2Client, err := mocketh2client.New(ctx)
	require.NoError(t, err)

	mockValidatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	mockSyncCommitteeAggregator := mocksynccommitteeaggregator.New()

	epoch := phase0.Epoch(100)
	slot := phase0.Slot(epoch * 32)
	validatorIndexToCommitteeIndices := testutil.CreateValidatorIndexToCommitteeIndicesTestData()
	validatorIndices := make([]phase0.ValidatorIndex, len(validatorIndexToCommitteeIndices))
	for validatorIndex := range validatorIndexToCommitteeIndices {
		validatorIndices[validatorIndex] = validatorIndex
	}

	mockSigner := mocksigner.New()
	mockSigs := make([]phase0.BLSSignature, len(validatorIndexToCommitteeIndices))

	// Ensure we have non-zero signatures.
	for i := range validatorIndexToCommitteeIndices {
		sig := mockSigs[i]
		sig[1] = 0x10
		mockSigs[i] = sig
	}
	mockSigner.PrimeSigs(mockSigs)

	duty := synccommitteemessenger.NewDuty(slot, validatorIndexToCommitteeIndices)
	accounts, err := testutil.CreateTestWalletAndAccounts(validatorIndices, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)

	for validIndex, testAccount := range accounts {
		duty.SetAccount(validIndex, testAccount)
		mockValidatingAccountsProvider.AddAccount(validIndex, testAccount)
	}

	tests := []struct {
		name   string
		params []standard.Parameter
	}{
		{
			name: "SetsLastSyncHead",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithProcessConcurrency(1),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithChainTimeService(chainTime),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSpecProvider(specProvider),
				standard.WithBeaconBlockRootProvider(mockETH2Client),
				standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithSyncCommitteeRootSigner(mockSigner),
				standard.WithSyncCommitteeSelectionSigner(mockSigner),
				standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			messageService, err := standard.New(ctx, test.params...)
			require.NoError(t, err)
			messages, msgErr := messageService.Message(ctx, duty)
			require.NoError(t, msgErr)
			require.NotEmpty(t, messages)
			lastReported, found := messageService.GetDataUsedForSlot(slot)
			require.Equal(t, true, found)
			beaconRootResponse, _ := mockETH2Client.BeaconBlockRoot(context.Background(), nil)
			expectedRoot := *beaconRootResponse.Data
			require.Equal(t, expectedRoot, lastReported.Root)
			require.Equal(t, validatorIndexToCommitteeIndices, lastReported.ValidatorToCommitteeIndex)
		})
	}
}

func TestServiceRemoveHistoricDataUsedForSlotValidation(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	nullSubmitter, err := nullsubmitter.New(ctx)
	require.NoError(t, err)
	mockETH2Client, err := mocketh2client.New(ctx)
	require.NoError(t, err)

	mockValidatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	mockSyncCommitteeAggregator := mocksynccommitteeaggregator.New()
	mockSigner := mocksigner.New()

	epoch := phase0.Epoch(100)
	slot := phase0.Slot(epoch * 32)

	params := []standard.Parameter{
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithProcessConcurrency(1),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithChainTimeService(chainTime),
		standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
		standard.WithSpecProvider(specProvider),
		standard.WithBeaconBlockRootProvider(mockETH2Client),
		standard.WithSyncCommitteeMessagesSubmitter(nullSubmitter),
		standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
		standard.WithSyncCommitteeRootSigner(mockSigner),
		standard.WithSyncCommitteeSelectionSigner(mockSigner),
		standard.WithSyncCommitteeSubscriptionsSubmitter(nullSubmitter),
	}
	tests := []struct {
		name                       string
		params                     []standard.Parameter
		dummyRecordsToCreate       int
		slotToVerifyBeforeAndAfter phase0.Slot
		removed                    bool
	}{
		{
			name:                       "SuccessfulCleanUp",
			params:                     params,
			dummyRecordsToCreate:       110,
			slotToVerifyBeforeAndAfter: phase0.Slot(50),
			removed:                    true,
		},
		{
			name:                       "CleanUpSkipped",
			params:                     params,
			dummyRecordsToCreate:       50,
			slotToVerifyBeforeAndAfter: phase0.Slot(32),
			removed:                    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			messageService, err := standard.New(ctx, test.params...)
			require.NoError(t, err)

			// Create historic records.
			for i := range test.dummyRecordsToCreate {
				historicSlot := slot - phase0.Slot(i)
				messageService.UpdateSyncCommitteeDataRecord(historicSlot, phase0.Root{}, nil)
			}
			if test.slotToVerifyBeforeAndAfter > 0 {
				_, found := messageService.GetDataUsedForSlot(slot - test.slotToVerifyBeforeAndAfter)
				require.Equal(t, true, found)
			}

			// Call the clean up method.
			messageService.RemoveHistoricDataUsedForSlotVerification(slot)

			// Assert we have removed the data.
			if test.slotToVerifyBeforeAndAfter > 0 {
				_, found := messageService.GetDataUsedForSlot(slot - test.slotToVerifyBeforeAndAfter)
				require.Equal(t, !test.removed, found)
			}
		})
	}
}
