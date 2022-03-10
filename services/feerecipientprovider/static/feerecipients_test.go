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

package static_test

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/feerecipientprovider/static"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestFeeRecipients(t *testing.T) {
	ctx := context.Background()
	recipient1 := bellatrix.ExecutionAddress{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	recipient2 := bellatrix.ExecutionAddress{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
	recipient3 := bellatrix.ExecutionAddress{0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33}
	defaultRecipient := bellatrix.ExecutionAddress{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	s, err := static.New(ctx,
		static.WithLogLevel(zerolog.Disabled),
		static.WithFeeRecipients(map[phase0.ValidatorIndex]bellatrix.ExecutionAddress{
			1: recipient1,
			2: recipient2,
			3: recipient3,
		}),
		static.WithDefaultFeeRecipient(defaultRecipient),
	)
	require.NoError(t, err)

	tests := []struct {
		name    string
		indices []phase0.ValidatorIndex
		res     map[phase0.ValidatorIndex]bellatrix.ExecutionAddress
		err     string
	}{
		{
			name:    "Default",
			indices: []phase0.ValidatorIndex{0},
			res: map[phase0.ValidatorIndex]bellatrix.ExecutionAddress{
				0: defaultRecipient,
			},
		},
		{
			name:    "KnownAndDefault",
			indices: []phase0.ValidatorIndex{0, 1},
			res: map[phase0.ValidatorIndex]bellatrix.ExecutionAddress{
				0: defaultRecipient,
				1: recipient1,
			},
		},
		{
			name:    "Known",
			indices: []phase0.ValidatorIndex{1, 2},
			res: map[phase0.ValidatorIndex]bellatrix.ExecutionAddress{
				1: recipient1,
				2: recipient2,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := s.FeeRecipients(ctx, test.indices)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}
