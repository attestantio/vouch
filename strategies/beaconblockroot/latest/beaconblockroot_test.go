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

package latest_test

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
	"github.com/attestantio/vouch/strategies/beaconblockroot/latest"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestBeaconBlockRoot(t *testing.T) {
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	blockToSlotCache := cacheSvc.(cache.BlockRootToSlotProvider)

	tests := []struct {
		name              string
		params            []latest.Parameter
		blockID           string
		slot              phase0.Slot
		subcommitteeIndex uint64
		beaconBlockRoot   phase0.Root
		err               string
		logEntries        []string
	}{
		{
			name: "Good",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.TraceLevel),
				latest.WithTimeout(2 * time.Second),
				latest.WithBeaconBlockRootProviders(map[string]eth2client.BeaconBlockRootProvider{
					"good": mock.NewBeaconBlockRootProvider(),
				}),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
			blockID: "1",
		},
		{
			name: "Timeout",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.TraceLevel),
				latest.WithTimeout(time.Second),
				latest.WithBeaconBlockRootProviders(map[string]eth2client.BeaconBlockRootProvider{
					"sleepy": mock.NewSleepyBeaconBlockRootProvider(5*time.Second, mock.NewBeaconBlockRootProvider()),
				}),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
			blockID: "1",
			err:     "no beacon block root received",
		},
		{
			name: "GoodMixed",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.TraceLevel),
				latest.WithTimeout(2 * time.Second),
				latest.WithBeaconBlockRootProviders(map[string]eth2client.BeaconBlockRootProvider{
					"error":  mock.NewErroringBeaconBlockRootProvider(),
					"sleepy": mock.NewSleepyBeaconBlockRootProvider(time.Second, mock.NewBeaconBlockRootProvider()),
				}),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
			blockID: "1",
		},
		{
			name: "SoftTimeoutWithResponses",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.TraceLevel),
				latest.WithTimeout(3 * time.Second),
				latest.WithBeaconBlockRootProviders(map[string]eth2client.BeaconBlockRootProvider{
					"good":   mock.NewBeaconBlockRootProvider(),
					"sleepy": mock.NewSleepyBeaconBlockRootProvider(2*time.Second, mock.NewBeaconBlockRootProvider()),
				}),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
			blockID:    "1",
			logEntries: []string{"Soft timeout reached with responses"},
		},
		{
			name: "SoftTimeoutWithoutResponses",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.TraceLevel),
				latest.WithTimeout(3 * time.Second),
				latest.WithBeaconBlockRootProviders(map[string]eth2client.BeaconBlockRootProvider{
					"sleepy": mock.NewSleepyBeaconBlockRootProvider(2*time.Second, mock.NewBeaconBlockRootProvider()),
				}),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
			blockID:    "1",
			logEntries: []string{"Soft timeout reached with no responses"},
		},
		{
			name: "SoftTimeoutWithError",
			params: []latest.Parameter{
				latest.WithLogLevel(zerolog.TraceLevel),
				latest.WithTimeout(3 * time.Second),
				latest.WithBeaconBlockRootProviders(map[string]eth2client.BeaconBlockRootProvider{
					"error":  mock.NewErroringBeaconBlockRootProvider(),
					"sleepy": mock.NewSleepyBeaconBlockRootProvider(2*time.Second, mock.NewBeaconBlockRootProvider()),
				}),
				latest.WithBlockRootToSlotCache(blockToSlotCache),
			},
			blockID:    "1",
			logEntries: []string{"Soft timeout reached with no responses"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			s, err := latest.New(context.Background(), test.params...)
			require.NoError(t, err)
			contribution, err := s.BeaconBlockRoot(context.Background(), &api.BeaconBlockRootOpts{
				Block: test.blockID,
			})
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, contribution)
			}
			for _, entry := range test.logEntries {
				capture.AssertHasEntry(t, entry)
			}
		})
	}
}
