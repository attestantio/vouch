// Copyright © 2020 Attestant Limited.
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

	"github.com/attestantio/vouch/services/graffitiprovider/static"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	tests := []struct {
		name   string
		params []static.Parameter
		err    string
	}{
		{
			name: "GraffitiMissing",
			params: []static.Parameter{
				static.WithLogLevel(zerolog.Disabled),
			},
		},
		{
			name: "GraffitiLong",
			params: []static.Parameter{
				static.WithLogLevel(zerolog.Disabled),
				static.WithGraffiti([]byte("123456789012345678901234567890123")),
			},
			err: "problem with parameters: graffiti has a maximum size of 32 bytes",
		},
		{
			name: "GraffitiShort",
			params: []static.Parameter{
				static.WithLogLevel(zerolog.Disabled),
				static.WithGraffiti([]byte("1234567890123456789012345678901")),
			},
		},
		{
			name: "Graffiti32",
			params: []static.Parameter{
				static.WithLogLevel(zerolog.Disabled),
				static.WithGraffiti([]byte("12345678901234567890123456789012")),
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
