// Copyright © 2025 Attestant Limited.
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

package combinedmajority_test

import (
	"context"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	cachepkg "github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/attestantio/vouch/strategies/attestationdata/combinedmajority"
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

	defaultCache := mockcache.New(map[phase0.Root]phase0.Slot{}).(cachepkg.BlockRootToSlotProvider)

	tests := []struct {
		name           string
		params         []combinedmajority.Parameter
		slot           phase0.Slot
		committeeIndex phase0.CommitteeIndex
		err            string
		logEntries     []string
	}{
		{
			name: "Good",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(2 * time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good": mock.NewAttestationDataProvider(),
				}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(defaultCache),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "Timeout",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"sleepy": mock.NewSleepyAttestationDataProvider(5*time.Second, mock.NewAttestationDataProvider()),
				}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(defaultCache),
			},
			slot:           12345,
			committeeIndex: 3,
			err:            "no attestation data received",
		},
		{
			name: "GoodMixed",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(2 * time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"error":  mock.NewErroringAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(time.Second, mock.NewAttestationDataProvider()),
				}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(defaultCache),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "BelowThreshold",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(2 * time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"error":       mock.NewErroringAttestationDataProvider(),
					"sleepy":      mock.NewSleepyAttestationDataProvider(time.Second, mock.NewAttestationDataProvider()),
					"sleepyError": mock.NewSleepyAttestationDataProvider(time.Second, mock.NewErroringAttestationDataProvider()),
					"good":        mock.NewAttestationDataProvider(),
				}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(defaultCache),
				combinedmajority.WithThreshold(3),
			},
			slot:           12345,
			committeeIndex: 3,
			err:            "majority attestation data count of 2 lower than threshold 3",
		},
		{
			name: "SoftTimeoutWithResponses",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(3 * time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good":   mock.NewAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(2*time.Second, mock.NewAttestationDataProvider()),
				}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(defaultCache),
			},
			slot:           12345,
			committeeIndex: 3,
			logEntries:     []string{"Soft timeout reached with responses"},
		},
		{
			name: "SoftTimeoutWithoutResponses",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(3 * time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"sleepy": mock.NewSleepyAttestationDataProvider(2*time.Second, mock.NewAttestationDataProvider()),
				}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(defaultCache),
			},
			slot:           12345,
			committeeIndex: 3,
			logEntries:     []string{"Soft timeout reached with no responses"},
		},
		{
			name: "SoftTimeoutWithError",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(3 * time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"error":  mock.NewErroringAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(2*time.Second, mock.NewAttestationDataProvider()),
				}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(defaultCache),
			},
			slot:           12345,
			committeeIndex: 3,
			logEntries:     []string{"Soft timeout reached with no responses"},
		},
		{
			name: "TwoMajoritiesOneFaulty",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(3 * time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good":   mock.NewAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(time.Second, mock.NewAttestationDataProvider()),
					"old":    mock.NewCustomAttestationDataProvider(-1, true),
					"error1": mock.NewErroringAttestationDataProvider(),
					"error2": mock.NewErroringAttestationDataProvider(),
					"error3": mock.NewErroringAttestationDataProvider(),
				}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(defaultCache),
				combinedmajority.WithThreshold(2),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "TwoMajorities",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(3 * time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"old":      mock.NewCustomAttestationDataProvider(-1, true),
					"new1":     mock.NewCustomAttestationDataProvider(1, true),
					"new2":     mock.NewCustomAttestationDataProvider(1, true),
					"current1": mock.NewAttestationDataProvider(),
					"old2":     mock.NewCustomAttestationDataProvider(-1, true),
				}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(defaultCache),
				combinedmajority.WithThreshold(2),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "NewMajoritySlotSelection",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(2 * time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"old":  mock.NewCustomAttestationDataProvider(-1, true), // slot - 1
					"new1": mock.NewCustomAttestationDataProvider(1, true),  // slot + 1, root based on slot+1
					"new2": mock.NewCustomAttestationDataProvider(1, false), // slot + 1, root based on requested_slot
				}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(NewMajoritySlotSelectionCache()),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "Empty",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(3 * time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"empty1": mock.NewEmptyAttestationDataProvider(),
					"empty2": mock.NewEmptyAttestationDataProvider(),
					"error":  mock.NewErroringAttestationDataProvider(),
				}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(defaultCache),
			},
			slot:           12345,
			committeeIndex: 3,
			err:            "no attestation data received",
		},
		{
			name: "ErrorAfterSoftTimeout",
			params: []combinedmajority.Parameter{
				combinedmajority.WithLogLevel(zerolog.TraceLevel),
				combinedmajority.WithTimeout(3 * time.Second),
				combinedmajority.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"sleepy": mock.NewSleepyAttestationDataProvider(2*time.Second, mock.NewErroringAttestationDataProvider()),
				}),
				combinedmajority.WithChainTime(chainTime),
				combinedmajority.WithBlockRootToSlotCache(defaultCache),
			},
			slot:           12345,
			committeeIndex: 3,
			logEntries:     []string{"Soft timeout reached with no responses"},
			err:            "no attestation data received",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			s, err := combinedmajority.New(context.Background(), test.params...)
			require.NoError(t, err)
			attestationData, err := s.AttestationData(context.Background(), &api.AttestationDataOpts{
				Slot:           test.slot,
				CommitteeIndex: test.committeeIndex,
			})
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

func NewMajoritySlotSelectionCache() cachepkg.BlockRootToSlotProvider {
	// Create pre-populated cache for NewMajoritySlotSelection test
	requestedSlot := phase0.Slot(12345)
	slotMappings := make(map[phase0.Root]phase0.Slot)

	// Root for new2 (changeRoot=false): based on requested_slot
	firstByte := byte(requestedSlot & 0xff)
	root1 := phase0.Root([32]byte{
		firstByte, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	})
	slotMappings[root1] = requestedSlot + 2 // Higher slot

	// Root for new1 (changeRoot=true): based on slot+1
	slot := requestedSlot + phase0.Slot(1)
	firstByte = byte(slot & 0xff)
	root2 := phase0.Root([32]byte{
		firstByte, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	})
	slotMappings[root2] = requestedSlot + 1 // Lower slot
	return mockcache.New(slotMappings).(cachepkg.BlockRootToSlotProvider)
}
