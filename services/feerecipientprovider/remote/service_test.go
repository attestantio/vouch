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

package remote_test

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/feerecipientprovider/static"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	feeRecipient := bellatrix.ExecutionAddress{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}

	tests := []struct {
		name   string
		params []static.Parameter
		err    string
	}{
		{
			name: "MonitorMissing",
			params: []static.Parameter{
				static.WithLogLevel(zerolog.Disabled),
				static.WithMonitor(nil),
				static.WithFeeRecipients(map[phase0.ValidatorIndex]bellatrix.ExecutionAddress{
					1: feeRecipient,
					2: feeRecipient,
				}),
				static.WithDefaultFeeRecipient(feeRecipient),
			},
			err: "problem with parameters: monitor not supplied",
		},
		{
			name: "DefaultFeeRecipientMissing",
			params: []static.Parameter{
				static.WithLogLevel(zerolog.Disabled),
			},
			err: "problem with parameters: default fee recipient not supplied",
		},
		{
			name: "Good",
			params: []static.Parameter{
				static.WithLogLevel(zerolog.Disabled),
				static.WithMonitor(nullmetrics.New(context.Background())),
				static.WithFeeRecipients(map[phase0.ValidatorIndex]bellatrix.ExecutionAddress{
					1: feeRecipient,
					2: feeRecipient,
				}),
				static.WithDefaultFeeRecipient(feeRecipient),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := static.New(context.Background(), test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
