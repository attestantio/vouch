// Copyright © 2023 - 2026 Attestant Limited.
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

package majority_test

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
	"github.com/attestantio/vouch/strategies/attestationdata/majority"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestAttestationData(t *testing.T) {
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

	cache := mockcache.New(map[phase0.Root]phase0.Slot{}).(cache.BlockRootToSlotProvider)

	tests := []struct {
		name           string
		params         []majority.Parameter
		slot           phase0.Slot
		committeeIndex phase0.CommitteeIndex
		err            string
		logEntries     []string
		// maxDuration, when set, is how long the call may take.
		maxDuration time.Duration
	}{
		{
			name: "Good",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(2 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good": mock.NewAttestationDataProvider(),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "Timeout",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"sleepy": mock.NewSleepyAttestationDataProvider(5*time.Second, mock.NewAttestationDataProvider()),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
			slot:           12345,
			committeeIndex: 3,
			err:            "no attestation data received",
		},
		{
			name: "GoodMixed",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(2 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"error":  mock.NewErroringAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(time.Second, mock.NewAttestationDataProvider()),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "ThresholdAllNodesAgree",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.Disabled),
				majority.WithTimeout(2 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good1": mock.NewAttestationDataProvider(),
					"good2": mock.NewAttestationDataProvider(),
					"good3": mock.NewAttestationDataProvider(),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
				majority.WithThreshold(3),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "ThresholdStrictMajority",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.Disabled),
				majority.WithTimeout(2 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good1": mock.NewAttestationDataProvider(),
					"good2": mock.NewAttestationDataProvider(),
					"other": mock.NewCustomAttestationDataProvider(1, true),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
				majority.WithThreshold(2),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "ThresholdWaitsForSlowNode",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.Disabled),
				majority.WithTimeout(3 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good1":  mock.NewAttestationDataProvider(),
					"good2":  mock.NewAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(time.Second, mock.NewAttestationDataProvider()),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
				majority.WithThreshold(3),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			// The third node answers after the soft timeout, so only the second wait collects it.
			name: "ThresholdWaitsPastSoftTimeout",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.Disabled),
				majority.WithTimeout(2 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good1":  mock.NewAttestationDataProvider(),
					"good2":  mock.NewAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(1500*time.Millisecond, mock.NewAttestationDataProvider()),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
				majority.WithThreshold(3),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "ThresholdNotReachedByTimeout",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.Disabled),
				majority.WithTimeout(time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good1":  mock.NewAttestationDataProvider(),
					"good2":  mock.NewAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(5*time.Second, mock.NewAttestationDataProvider()),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
				majority.WithThreshold(3),
			},
			slot:           12345,
			committeeIndex: 3,
			err:            "majority attestation data count of 2 lower than threshold 3",
		},
		{
			// The slow node is not waited for once a strict majority agrees.
			name: "ReturnsOnceStrictMajorityAgrees",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.Disabled),
				majority.WithTimeout(4 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good1":  mock.NewAttestationDataProvider(),
					"good2":  mock.NewAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(3*time.Second, mock.NewAttestationDataProvider()),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
			slot:           12345,
			committeeIndex: 3,
			maxDuration:    time.Second,
		},
		{
			// The slow node is not waited for once the threshold is met.
			name: "ReturnsOnceThresholdMet",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.Disabled),
				majority.WithTimeout(4 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good1":  mock.NewAttestationDataProvider(),
					"good2":  mock.NewAttestationDataProvider(),
					"good3":  mock.NewAttestationDataProvider(),
					"good4":  mock.NewAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(3*time.Second, mock.NewAttestationDataProvider()),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
				majority.WithThreshold(4),
			},
			slot:           12345,
			committeeIndex: 3,
			maxDuration:    time.Second,
		},
		{
			// No node is left to answer, so waiting for the threshold would only run out the timeout.
			name: "ReturnsOnceEveryNodeAnswered",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.Disabled),
				majority.WithTimeout(4 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good1": mock.NewAttestationDataProvider(),
					"good2": mock.NewAttestationDataProvider(),
					"error": mock.NewErroringAttestationDataProvider(),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
				majority.WithThreshold(3),
			},
			slot:           12345,
			committeeIndex: 3,
			err:            "majority attestation data count of 2 lower than threshold 3",
			maxDuration:    time.Second,
		},
		{
			name: "SoftTimeoutWithResponses",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(3 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good":   mock.NewAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(2*time.Second, mock.NewAttestationDataProvider()),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
			slot:           12345,
			committeeIndex: 3,
			logEntries:     []string{"Soft timeout reached with responses"},
		},
		{
			name: "SoftTimeoutWithoutResponses",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(3 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"sleepy": mock.NewSleepyAttestationDataProvider(2*time.Second, mock.NewAttestationDataProvider()),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
			slot:           12345,
			committeeIndex: 3,
			logEntries:     []string{"Soft timeout reached with no responses"},
		},
		{
			name: "SoftTimeoutWithError",
			params: []majority.Parameter{
				majority.WithLogLevel(zerolog.TraceLevel),
				majority.WithTimeout(3 * time.Second),
				majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"error":  mock.NewErroringAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(2*time.Second, mock.NewAttestationDataProvider()),
				}),
				majority.WithChainTime(chainTime),
				majority.WithBlockRootToSlotCache(cache),
			},
			slot:           12345,
			committeeIndex: 3,
			logEntries:     []string{"Soft timeout reached with no responses"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			s, err := majority.New(context.Background(), test.params...)
			require.NoError(t, err)
			started := time.Now()
			attestationData, err := s.AttestationData(context.Background(), &api.AttestationDataOpts{
				Slot:           test.slot,
				CommitteeIndex: test.committeeIndex,
			})
			if test.maxDuration > 0 {
				require.Less(t, time.Since(started), test.maxDuration)
			}
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, attestationData)
			}
			for _, entry := range test.logEntries {
				capture.AssertHasEntry(t, entry)
			}
		})
	}
}

// TestAttestationDataMajorityAfterSoftTimeout proves nodes that answer after the soft timeout are still
// collected until a strict majority agrees: two early nodes disagree with the three later ones.
func TestAttestationDataMajorityAfterSoftTimeout(t *testing.T) {
	ctx := context.Background()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(mock.NewSpecProvider()),
	)
	require.NoError(t, err)

	late := mock.NewCustomAttestationDataProvider(1, true)
	s, err := majority.New(ctx,
		majority.WithLogLevel(zerolog.Disabled),
		majority.WithTimeout(4*time.Second),
		majority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
			"early1": mock.NewAttestationDataProvider(),
			"early2": mock.NewAttestationDataProvider(),
			"late1":  mock.NewSleepyAttestationDataProvider(3*time.Second, late),
			"late2":  mock.NewSleepyAttestationDataProvider(3*time.Second, late),
			"late3":  mock.NewSleepyAttestationDataProvider(3*time.Second, late),
		}),
		majority.WithChainTime(chainTime),
		majority.WithBlockRootToSlotCache(mockcache.New(map[phase0.Root]phase0.Slot{}).(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := s.AttestationData(ctx, &api.AttestationDataOpts{Slot: 12345, CommitteeIndex: 3})
	require.NoError(t, err)
	require.Equal(t, phase0.Slot(12346), response.Data.Slot)
}
