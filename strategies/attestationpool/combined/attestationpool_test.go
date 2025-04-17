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

package combined_test

import (
	"context"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/strategies/attestationpool/combined"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestAttestationPool(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		params         []combined.Parameter
		slot           phase0.Slot
		committeeIndex phase0.CommitteeIndex
		err            string
		logEntries     []string
	}{
		{
			name: "Good",
			params: []combined.Parameter{
				combined.WithLogLevel(zerolog.TraceLevel),
				combined.WithTimeout(2 * time.Second),
				combined.WithAttestationPoolProviders(map[string]eth2client.AttestationPoolProvider{
					"good": mock.NewAttestationPoolProvider(),
				}),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "Timeout",
			params: []combined.Parameter{
				combined.WithLogLevel(zerolog.TraceLevel),
				combined.WithTimeout(time.Second),
				combined.WithAttestationPoolProviders(map[string]eth2client.AttestationPoolProvider{
					"sleepy": mock.NewSleepyAttestationPoolProvider(5*time.Second, mock.NewAttestationPoolProvider()),
				}),
			},
			slot:           12345,
			committeeIndex: 3,
			err:            "no responses received",
		},
		{
			name: "GoodMixed",
			params: []combined.Parameter{
				combined.WithLogLevel(zerolog.TraceLevel),
				combined.WithTimeout(2 * time.Second),
				combined.WithAttestationPoolProviders(map[string]eth2client.AttestationPoolProvider{
					"error":  mock.NewErroringAttestationPoolProvider(),
					"sleepy": mock.NewSleepyAttestationPoolProvider(time.Second, mock.NewAttestationPoolProvider()),
				}),
			},
			slot:           12345,
			committeeIndex: 3,
		},
		{
			name: "SoftTimeoutWithResponses",
			params: []combined.Parameter{
				combined.WithLogLevel(zerolog.TraceLevel),
				combined.WithTimeout(3 * time.Second),
				combined.WithAttestationPoolProviders(map[string]eth2client.AttestationPoolProvider{
					"good":   mock.NewAttestationPoolProvider(),
					"sleepy": mock.NewSleepyAttestationPoolProvider(2*time.Second, mock.NewAttestationPoolProvider()),
				}),
			},
			slot:           12345,
			committeeIndex: 3,
			logEntries:     []string{"Soft timeout reached with responses"},
		},
		{
			name: "SoftTimeoutWithoutResponses",
			params: []combined.Parameter{
				combined.WithLogLevel(zerolog.TraceLevel),
				combined.WithTimeout(3 * time.Second),
				combined.WithAttestationPoolProviders(map[string]eth2client.AttestationPoolProvider{
					"sleepy": mock.NewSleepyAttestationPoolProvider(2*time.Second, mock.NewAttestationPoolProvider()),
				}),
			},
			slot:           12345,
			committeeIndex: 3,
			logEntries:     []string{"Soft timeout reached with no responses"},
		},
		{
			name: "SoftTimeoutWithError",
			params: []combined.Parameter{
				combined.WithLogLevel(zerolog.TraceLevel),
				combined.WithTimeout(3 * time.Second),
				combined.WithAttestationPoolProviders(map[string]eth2client.AttestationPoolProvider{
					"error":  mock.NewErroringAttestationPoolProvider(),
					"sleepy": mock.NewSleepyAttestationPoolProvider(2*time.Second, mock.NewAttestationPoolProvider()),
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
			s, err := combined.New(ctx, test.params...)
			require.NoError(t, err)
			attestationPoolResponse, err := s.AttestationPool(context.Background(), &api.AttestationPoolOpts{})
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, attestationPoolResponse)
			}
			for _, entry := range test.logEntries {
				capture.AssertHasEntry(t, entry)
			}
		})
	}
}
