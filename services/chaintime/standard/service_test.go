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

package standard_test

import (
	"context"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestService(t *testing.T) {
	genesisTime := time.Now()
	mockGenesisProvider := mock.NewGenesisProvider(genesisTime)
	mockSpecProvider := mock.NewSpecProvider()

	tests := []struct {
		name   string
		params []standard.Parameter
		err    string
	}{
		{
			name: "GenesisProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithSpecProvider(mockSpecProvider),
			},
			err: "problem with parameters: no genesis provider specified",
		},
		{
			name: "SpecProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithGenesisProvider(mockGenesisProvider),
			},
			err: "problem with parameters: no spec provider specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithGenesisProvider(mockGenesisProvider),
				standard.WithSpecProvider(mockSpecProvider),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := standard.New(context.Background(), test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func createMockService(genesisTime time.Time) (chaintime.Service, error) {
	mockGenesisProvider := mock.NewGenesisProvider(genesisTime)
	mockSpecProvider := mock.NewSpecProvider()
	s, err := standard.New(context.Background(),
		standard.WithGenesisProvider(mockGenesisProvider),
		standard.WithSpecProvider(mockSpecProvider),
	)
	return s, err
}

func TestGenesisTime(t *testing.T) {
	genesisTime := time.Now()

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, genesisTime, s.GenesisTime())
}

func TestStartOfSlot(t *testing.T) {
	slotDuration := 12 * time.Second
	genesisTime := time.Now()

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, genesisTime, s.StartOfSlot(0))
	require.Equal(t, genesisTime.Add(1000*slotDuration), s.StartOfSlot(1000))
}

func TestStartOfEpoch(t *testing.T) {
	slotDuration := 12 * time.Second
	slotsPerEpoch := uint64(32)
	genesisTime := time.Now()

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, genesisTime, s.StartOfEpoch(0))
	require.Equal(t, genesisTime.Add(time.Duration(1000*slotsPerEpoch)*slotDuration), s.StartOfEpoch(1000))
}

func TestCurrentSlot(t *testing.T) {
	slotDuration := 12 * time.Second
	genesisTime := time.Now().Add(-5 * slotDuration)

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, phase0.Slot(5), s.CurrentSlot())
}

func TestCurrentSlotPreGenesis(t *testing.T) {
	genesisTime := time.Now().Add(3 * time.Hour)

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, phase0.Slot(0), s.CurrentSlot())
}

func TestCurrentEpoch(t *testing.T) {
	slotDuration := 12 * time.Second
	slotsPerEpoch := uint64(32)
	genesisTime := time.Now().Add(time.Duration(int64(-2)*int64(slotsPerEpoch)) * slotDuration)

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, phase0.Epoch(2), s.CurrentEpoch())
}

func TestCurrentEpochPreGenesis(t *testing.T) {
	genesisTime := time.Now().Add(3 * time.Hour)

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	require.Equal(t, phase0.Epoch(0), s.CurrentEpoch())
}

func TestSlotToEpoch(t *testing.T) {
	tests := []struct {
		name  string
		slot  phase0.Slot
		epoch phase0.Epoch
	}{
		{
			name:  "ZeroFirstSlot",
			slot:  0,
			epoch: 0,
		},
		{
			name:  "ZeroLastSlot",
			slot:  31,
			epoch: 0,
		},
		{
			name:  "OneFirstSlot",
			slot:  32,
			epoch: 1,
		},
	}

	genesisTime := time.Now()

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			epoch := s.SlotToEpoch(test.slot)
			assert.Equal(t, test.epoch, epoch)
		})
	}
}

func TestFirstSlotOfEpoch(t *testing.T) {
	tests := []struct {
		name  string
		epoch phase0.Epoch
		slot  phase0.Slot
	}{
		{
			name:  "Zero",
			epoch: 0,
			slot:  0,
		},
		{
			name:  "One",
			epoch: 1,
			slot:  32,
		},
		{
			name:  "OneThousand",
			epoch: 1000,
			slot:  32000,
		},
	}

	genesisTime := time.Now()

	s, err := createMockService(genesisTime)
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			slot := s.FirstSlotOfEpoch(test.epoch)
			assert.Equal(t, test.slot, slot)
		})
	}
}
