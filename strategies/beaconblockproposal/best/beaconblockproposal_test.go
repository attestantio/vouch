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

package best_test

import (
	"context"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/attestantio/vouch/strategies/beaconblockproposal/best"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestProposal(t *testing.T) {
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

	signedBeaconBlockProvider := mock.NewSignedBeaconBlockProvider()
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	blockToSlotCache := cacheSvc.(cache.BlockRootToSlotProvider)

	tests := []struct {
		name           string
		params         []best.Parameter
		slot           phase0.Slot
		committeeIndex phase0.CommitteeIndex
		err            string
		logEntries     []string
	}{
		{
			name: "Good",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(2 * time.Second),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(2),
				best.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"good": mock.NewProposalProvider(),
				}),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "Timeout",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(time.Second),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(2),
				best.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"sleepy": mock.NewSleepyProposalProvider(5*time.Second, mock.NewProposalProvider()),
				}),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			slot:           12345,
			committeeIndex: 3,
			err:            "no proposals received",
		},
		{
			name: "GoodMixed",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(2 * time.Second),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(2),
				best.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"error":  mock.NewErroringProposalProvider(),
					"sleepy": mock.NewSleepyProposalProvider(time.Second, mock.NewProposalProvider()),
				}),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "SoftTimeoutWithResponses",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(3 * time.Second),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(2),
				best.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"good":   mock.NewProposalProvider(),
					"sleepy": mock.NewSleepyProposalProvider(2*time.Second, mock.NewProposalProvider()),
				}),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			slot:           12345,
			committeeIndex: 3,
			logEntries:     []string{"Soft timeout reached with responses"},
		},
		{
			name: "SoftTimeoutWithoutResponses",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(3 * time.Second),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(2),
				best.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"sleepy": mock.NewSleepyProposalProvider(2*time.Second, mock.NewProposalProvider()),
				}),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			slot:           12345,
			committeeIndex: 3,
			logEntries:     []string{"Soft timeout reached with no responses"},
		},
		{
			name: "SoftTimeoutWithError",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(3 * time.Second),
				best.WithEventsProvider(mock.NewEventsProvider()),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProcessConcurrency(2),
				best.WithSignedBeaconBlockProvider(signedBeaconBlockProvider),
				best.WithProposalProviders(map[string]eth2client.ProposalProvider{
					"error":  mock.NewErroringProposalProvider(),
					"sleepy": mock.NewSleepyProposalProvider(2*time.Second, mock.NewProposalProvider()),
				}),
				best.WithBlockRootToSlotCache(blockToSlotCache),
			},
			slot:           12345,
			committeeIndex: 3,
			logEntries:     []string{"Soft timeout reached with no responses"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			s, err := best.New(context.Background(), test.params...)
			require.NoError(t, err)
			proposal, err := s.Proposal(context.Background(), &api.ProposalOpts{
				Slot: 12345,
				RandaoReveal: phase0.BLSSignature([96]byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
					0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
					0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
					0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
				}),
			})
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, proposal)
			}
			for _, entry := range test.logEntries {
				capture.AssertHasEntry(t, entry)
			}
		})
	}
}
