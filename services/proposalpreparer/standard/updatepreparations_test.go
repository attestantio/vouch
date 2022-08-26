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

package standard_test

import (
	"context"
	"testing"
	"time"

	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	mockblockrelay "github.com/attestantio/vouch/services/blockrelay/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/attestantio/vouch/services/proposalpreparer/standard"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestUpdatePreparations(t *testing.T) {
	ctx := context.Background()

	zerolog.SetGlobalLevel(zerolog.Disabled)

	genesisTime := time.Now()
	slotDuration := 12 * time.Second
	slotsPerEpoch := uint64(32)
	genesisTimeProvider := mock.NewGenesisTimeProvider(genesisTime)
	slotDurationProvider := mock.NewSlotDurationProvider(slotDuration)
	slotsPerEpochProvider := mock.NewSlotsPerEpochProvider(slotsPerEpoch)

	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithGenesisTimeProvider(genesisTimeProvider),
		standardchaintime.WithSlotDurationProvider(slotDurationProvider),
		standardchaintime.WithSlotsPerEpochProvider(slotsPerEpochProvider),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		params   []standard.Parameter
		err      string
		logEntry string
	}{
		{
			name: "ErroringAccountManager",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(mockaccountmanager.NewErroringValidatingAccountsProvider()),
				standard.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				standard.WithExecutionConfigProvider(mockblockrelay.New()),
			},
			err: "failed to obtain validating accounts: error",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithChainTimeService(chainTime),
				standard.WithValidatingAccountsProvider(mockaccountmanager.NewValidatingAccountsProvider()),
				standard.WithProposalPreparationsSubmitter(mock.NewProposalPreparationsSubmitter()),
				standard.WithExecutionConfigProvider(mockblockrelay.New()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			s, err := standard.New(ctx, test.params...)
			require.NoError(t, err)
			err = s.UpdatePreparations(ctx)
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
