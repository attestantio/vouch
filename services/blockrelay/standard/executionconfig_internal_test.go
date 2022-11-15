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

package standard

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/blockrelay"
	"github.com/stretchr/testify/require"
)

func address(input string) bellatrix.ExecutionAddress {
	data, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		panic(err)
	}
	executionAddress := bellatrix.ExecutionAddress{}
	copy(executionAddress[:], data)
	return executionAddress
}

func TestNormaliseExecutionConfig(t *testing.T) {
	ctx := context.Background()
	// require.NoError(t, e2types.InitBLS())

	s := &Service{
		fallbackFeeRecipient: address("0x000102030405060708090a0b0c0d0e0f10111213"),
		fallbackGasLimit:     12345,
	}

	tests := []struct {
		name            string
		executionConfig *blockrelay.ExecutionConfig
		expectedConfig  *blockrelay.ExecutionConfig
	}{
		{
			name:            "Fallbacks",
			executionConfig: &blockrelay.ExecutionConfig{},
			expectedConfig: &blockrelay.ExecutionConfig{
				DefaultConfig: &blockrelay.ProposerConfig{
					FeeRecipient: s.fallbackFeeRecipient,
					GasLimit:     s.fallbackGasLimit,
					Builder:      &blockrelay.BuilderConfig{},
				},
			},
		},
		{
			name: "Defaults",
			executionConfig: &blockrelay.ExecutionConfig{
				DefaultConfig: &blockrelay.ProposerConfig{
					FeeRecipient: address("0x1010101010101010101010101010101010101010"),
					GasLimit:     11111,
					Builder: &blockrelay.BuilderConfig{
						Enabled: true,
						Relays:  []string{"1", "2", "3"},
					},
				},
				ProposerConfigs: map[phase0.BLSPubKey]*blockrelay.ProposerConfig{
					*pubkey("0x00000001d3010778cd08ee514b08fe67b6c503b510987a4ce43f42306d97c67c"): nil,
				},
			},
			expectedConfig: &blockrelay.ExecutionConfig{
				DefaultConfig: &blockrelay.ProposerConfig{
					FeeRecipient: address("0x1010101010101010101010101010101010101010"),
					GasLimit:     11111,
					Builder: &blockrelay.BuilderConfig{
						Enabled: true,
						Relays:  []string{"1", "2", "3"},
					},
				},
				ProposerConfigs: map[phase0.BLSPubKey]*blockrelay.ProposerConfig{
					*pubkey("0x00000001d3010778cd08ee514b08fe67b6c503b510987a4ce43f42306d97c67c"): {
						FeeRecipient: address("0x1010101010101010101010101010101010101010"),
						GasLimit:     11111,
						Builder: &blockrelay.BuilderConfig{
							Enabled: true,
							Relays:  []string{"1", "2", "3"},
						},
					},
				},
			},
		},
		{
			name: "Explicit",
			executionConfig: &blockrelay.ExecutionConfig{
				DefaultConfig: &blockrelay.ProposerConfig{
					FeeRecipient: address("0x1010101010101010101010101010101010101010"),
					GasLimit:     11111,
					Builder: &blockrelay.BuilderConfig{
						Enabled: true,
						Relays:  []string{"1", "2", "3"},
					},
				},
				ProposerConfigs: map[phase0.BLSPubKey]*blockrelay.ProposerConfig{
					*pubkey("0x00000001d3010778cd08ee514b08fe67b6c503b510987a4ce43f42306d97c67c"): {
						FeeRecipient: address("0x2020202020202020202020202020202020202020"),
						GasLimit:     22222,
						Builder: &blockrelay.BuilderConfig{
							Enabled: true,
							Relays:  []string{"4", "5", "6"},
						},
					},
				},
			},
			expectedConfig: &blockrelay.ExecutionConfig{
				DefaultConfig: &blockrelay.ProposerConfig{
					FeeRecipient: address("0x1010101010101010101010101010101010101010"),
					GasLimit:     11111,
					Builder: &blockrelay.BuilderConfig{
						Enabled: true,
						Relays:  []string{"1", "2", "3"},
					},
				},
				ProposerConfigs: map[phase0.BLSPubKey]*blockrelay.ProposerConfig{
					*pubkey("0x00000001d3010778cd08ee514b08fe67b6c503b510987a4ce43f42306d97c67c"): {
						FeeRecipient: address("0x2020202020202020202020202020202020202020"),
						GasLimit:     22222,
						Builder: &blockrelay.BuilderConfig{
							Enabled: true,
							Relays:  []string{"4", "5", "6"},
						},
					},
				},
			},
		},
		{
			name: "ExplicitLocalBuilder",
			executionConfig: &blockrelay.ExecutionConfig{
				DefaultConfig: &blockrelay.ProposerConfig{
					FeeRecipient: address("0x1010101010101010101010101010101010101010"),
					GasLimit:     11111,
					Builder: &blockrelay.BuilderConfig{
						Enabled: true,
						Relays:  []string{"1", "2", "3"},
					},
				},
				ProposerConfigs: map[phase0.BLSPubKey]*blockrelay.ProposerConfig{
					*pubkey("0x00000001d3010778cd08ee514b08fe67b6c503b510987a4ce43f42306d97c67c"): {
						FeeRecipient: address("0x2020202020202020202020202020202020202020"),
						GasLimit:     22222,
						Builder: &blockrelay.BuilderConfig{
							Enabled: false,
						},
					},
				},
			},
			expectedConfig: &blockrelay.ExecutionConfig{
				DefaultConfig: &blockrelay.ProposerConfig{
					FeeRecipient: address("0x1010101010101010101010101010101010101010"),
					GasLimit:     11111,
					Builder: &blockrelay.BuilderConfig{
						Enabled: true,
						Relays:  []string{"1", "2", "3"},
					},
				},
				ProposerConfigs: map[phase0.BLSPubKey]*blockrelay.ProposerConfig{
					*pubkey("0x00000001d3010778cd08ee514b08fe67b6c503b510987a4ce43f42306d97c67c"): {
						FeeRecipient: address("0x2020202020202020202020202020202020202020"),
						GasLimit:     22222,
						Builder: &blockrelay.BuilderConfig{
							Enabled: false,
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s.normaliseExecutionConfig(ctx, test.executionConfig)
			require.Equal(t, test.expectedConfig, test.executionConfig)
		})
	}
}
