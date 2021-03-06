// Copyright © 2021 Attestant Limited.
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
	mockaccountsprovider "github.com/attestantio/vouch/services/accountmanager/mock"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/beaconblockproposer/standard"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestProposeNoRANDAOReveal(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()

	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithGenesisTimeProvider(mock.NewGenesisTimeProvider(time.Now())),
		standardchaintime.WithSlotDurationProvider(mock.NewSlotDurationProvider(12*time.Second)),
		standardchaintime.WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
	)
	require.NoError(t, err)

	s, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.TraceLevel),
		standard.WithMonitor(nullmetrics.New(ctx)),
		standard.WithProposalDataProvider(mock.NewBeaconBlockProposalProvider()),
		standard.WithChainTimeService(chainTime),
		standard.WithValidatingAccountsProvider(mockaccountsprovider.New()),
		standard.WithBeaconBlockSubmitter(mock.NewBeaconBlockSubmitter()),
		standard.WithRANDAORevealSigner(mocksigner.New()),
		standard.WithBeaconBlockSigner(mocksigner.New()),
	)
	require.NoError(t, err)

	s.Propose(ctx, &beaconblockproposer.Duty{})
	capture.AssertHasEntry(t, "Missing RANDAO reveal")
}
