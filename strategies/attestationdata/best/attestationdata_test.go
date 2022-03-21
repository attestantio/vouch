// Copyright © 2020, 2021 Attestant Limited.
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
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/strategies/attestationdata/best"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestAttestationData(t *testing.T) {
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
				best.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good": mock.NewAttestationDataProvider(),
				}),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "Timeout",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(time.Second),
				best.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"sleepy": mock.NewSleepyAttestationDataProvider(5*time.Second, mock.NewAttestationDataProvider()),
				}),
			},
			slot:           12345,
			committeeIndex: 3,
			err:            "no attestations received",
		},
		{
			name: "NilResponse",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(time.Second),
				best.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"nil": mock.NewNilAttestationDataProvider(),
				}),
			},
			slot:           12345,
			committeeIndex: 3,
			err:            "no attestations received",
		},
		{
			name: "GoodMixed",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(2 * time.Second),
				best.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"error":  mock.NewErroringAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(time.Second, mock.NewAttestationDataProvider()),
				}),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "SoftTimeoutWithResponses",
			params: []best.Parameter{
				best.WithLogLevel(zerolog.TraceLevel),
				best.WithTimeout(3 * time.Second),
				best.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"good":   mock.NewAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(2*time.Second, mock.NewAttestationDataProvider()),
				}),
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
				best.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"sleepy": mock.NewSleepyAttestationDataProvider(2*time.Second, mock.NewAttestationDataProvider()),
				}),
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
				best.WithAttestationDataProviders(map[string]eth2client.AttestationDataProvider{
					"error":  mock.NewErroringAttestationDataProvider(),
					"sleepy": mock.NewSleepyAttestationDataProvider(2*time.Second, mock.NewAttestationDataProvider()),
				}),
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
			attestationData, err := s.AttestationData(context.Background(), test.slot, test.committeeIndex)
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
