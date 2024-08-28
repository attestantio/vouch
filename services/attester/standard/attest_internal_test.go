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

package standard

import (
	"context"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	"github.com/attestantio/vouch/services/attester"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	prometheusmetrics "github.com/attestantio/vouch/services/metrics/prometheus"
	mocksigner "github.com/attestantio/vouch/services/signer/mock"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestCreateAttestations(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	attestationDataProvider := mock.NewAttestationDataProvider()
	attestationsSubmitter := mock.NewAttestationsSubmitter()
	beaconAttestationsSigner := mocksigner.New()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	validatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	prometheusMetrics, err := prometheusmetrics.New(ctx,
		prometheusmetrics.WithAddress(":12345"),
	)
	require.NoError(t, err)

	capture := logger.NewLogCapture()
	s, err := New(ctx,
		WithLogLevel(zerolog.InfoLevel),
		WithMonitor(prometheusMetrics),
		WithProcessConcurrency(1),
		WithChainTime(chainTime),
		WithSpecProvider(specProvider),
		WithAttestationDataProvider(attestationDataProvider),
		WithAttestationsSubmitter(attestationsSubmitter),
		WithValidatingAccountsProvider(validatingAccountsProvider),
		WithBeaconAttestationsSigner(beaconAttestationsSigner),
	)
	require.NoError(t, err)

	duty, err := attester.NewDuty(ctx,
		100,                                    // slot.
		1,                                      // committee at slot,
		[]phase0.ValidatorIndex{0},             // validator indices.
		[]phase0.CommitteeIndex{0},             // committee indices.
		[]uint64{0},                            // committee indices.
		map[phase0.CommitteeIndex]uint64{0: 0}, // committee lengths.
	)
	require.NoError(t, err)

	bitlist1 := bitfield.NewBitlist(128)
	bitlist1.SetBitAt(123, true)

	tests := []struct {
		name                      string
		duty                      *attester.Duty
		committeeIndices          []phase0.CommitteeIndex
		validatorCommitteeIndices []phase0.ValidatorIndex
		committeeSizes            []uint64
		data                      *phase0.AttestationData
		sigs                      []phase0.BLSSignature
		expected                  []*phase0.Attestation
		err                       string
		logEntries                []string
	}{
		{
			name:     "NoAttestations",
			expected: []*phase0.Attestation{},
		},
		{
			name: "ZeroSig",
			sigs: []phase0.BLSSignature{
				{},
			},
			expected:   []*phase0.Attestation{},
			logEntries: []string{"No signature for validator; not creating attestation"},
		},
		{
			name:                      "WithAttestations",
			duty:                      duty,
			committeeIndices:          []phase0.CommitteeIndex{1},
			validatorCommitteeIndices: []phase0.ValidatorIndex{123},
			committeeSizes:            []uint64{128},
			data: &phase0.AttestationData{
				Slot:            100,
				Index:           1,
				BeaconBlockRoot: phase0.Root{0x02},
				Source: &phase0.Checkpoint{
					Epoch: 3,
					Root:  phase0.Root{0x03},
				},
				Target: &phase0.Checkpoint{
					Epoch: 4,
					Root:  phase0.Root{0x04},
				},
			},
			sigs: []phase0.BLSSignature{
				{0x01},
			},
			expected: []*phase0.Attestation{
				{
					AggregationBits: bitlist1,
					Data: &phase0.AttestationData{
						Slot:            100,
						Index:           1,
						BeaconBlockRoot: phase0.Root{0x02},
						Source: &phase0.Checkpoint{
							Epoch: 3,
							Root:  phase0.Root{0x03},
						},
						Target: &phase0.Checkpoint{
							Epoch: 4,
							Root:  phase0.Root{0x04},
						},
					},
					Signature: phase0.BLSSignature{0x01},
				},
			},
		},
	}

	for _, test := range tests {
		ctx := context.Background()
		t.Run(test.name, func(t *testing.T) {
			attestations := s.createAttestations(ctx, test.duty, test.committeeIndices, test.validatorCommitteeIndices, test.committeeSizes, test.data, test.sigs)
			require.Equal(t, test.expected, attestations)
			for _, entry := range test.logEntries {
				capture.AssertHasEntry(t, entry)
			}
		})
	}
}

func TestValidateAttestationData(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	attestationDataProvider := mock.NewAttestationDataProvider()
	attestationsSubmitter := mock.NewAttestationsSubmitter()
	beaconAttestationsSigner := mocksigner.New()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	validatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	prometheusMetrics, err := prometheusmetrics.New(ctx,
		prometheusmetrics.WithAddress(":12345"),
	)
	require.NoError(t, err)

	capture := logger.NewLogCapture()
	s, err := New(ctx,
		WithLogLevel(zerolog.Disabled),
		WithMonitor(prometheusMetrics),
		WithProcessConcurrency(1),
		WithChainTime(chainTime),
		WithSpecProvider(specProvider),
		WithAttestationDataProvider(attestationDataProvider),
		WithAttestationsSubmitter(attestationsSubmitter),
		WithValidatingAccountsProvider(validatingAccountsProvider),
		WithBeaconAttestationsSigner(beaconAttestationsSigner),
	)
	require.NoError(t, err)

	duty, err := attester.NewDuty(ctx,
		100,                                    // slot.
		1,                                      // committee at slot,
		[]phase0.ValidatorIndex{0},             // validator indices.
		[]phase0.CommitteeIndex{0},             // committee indices.
		[]uint64{0},                            // committee indices.
		map[phase0.CommitteeIndex]uint64{0: 0}, // committee lengths.
	)
	require.NoError(t, err)

	tests := []struct {
		name            string
		duty            *attester.Duty
		attestationData *phase0.AttestationData
		err             string
		logEntries      []string
	}{
		{
			name: "SlotMismatch",
			duty: duty,
			attestationData: &phase0.AttestationData{
				Slot:  101,
				Index: 0,
				Source: &phase0.Checkpoint{
					Epoch: 2,
				},
				Target: &phase0.Checkpoint{
					Epoch: 3,
				},
			},
			err: "attestation request for slot 100 returned data for slot 101",
		},
		{
			name: "SourceEpochIncorrect",
			duty: duty,
			attestationData: &phase0.AttestationData{
				Slot:  100,
				Index: 0,
				Source: &phase0.Checkpoint{
					Epoch: 4,
				},
				Target: &phase0.Checkpoint{
					Epoch: 2,
				},
			},
			err: "attestation request for slot 100 returned source epoch 4 greater than target epoch 2",
		},
		{
			name: "TargetEpochIncorrect",
			duty: duty,
			attestationData: &phase0.AttestationData{
				Slot:  100,
				Index: 0,
				Source: &phase0.Checkpoint{
					Epoch: 2,
				},
				Target: &phase0.Checkpoint{
					Epoch: 4,
				},
			},
			err: "attestation request for slot 100 returned target epoch 4 greater than current epoch 3",
		},
		{
			name: "Good",
			duty: duty,
			attestationData: &phase0.AttestationData{
				Slot:  100,
				Index: 0,
				Source: &phase0.Checkpoint{
					Epoch: 2,
				},
				Target: &phase0.Checkpoint{
					Epoch: 3,
				},
			},
		},
	}

	for _, test := range tests {
		ctx := context.Background()
		t.Run(test.name, func(t *testing.T) {
			err := s.validateAttestationData(ctx, test.duty, test.attestationData)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
			for _, entry := range test.logEntries {
				capture.AssertHasEntry(t, entry)
			}
		})
	}
}

func TestHousekeepAttestedMap(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	attestationDataProvider := mock.NewAttestationDataProvider()
	attestationsSubmitter := mock.NewAttestationsSubmitter()
	beaconAttestationsSigner := mocksigner.New()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	validatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	prometheusMetrics, err := prometheusmetrics.New(ctx,
		prometheusmetrics.WithAddress(":12345"),
	)
	require.NoError(t, err)

	s, err := New(ctx,
		WithLogLevel(zerolog.Disabled),
		WithMonitor(prometheusMetrics),
		WithProcessConcurrency(1),
		WithChainTime(chainTime),
		WithSpecProvider(specProvider),
		WithAttestationDataProvider(attestationDataProvider),
		WithAttestationsSubmitter(attestationsSubmitter),
		WithValidatingAccountsProvider(validatingAccountsProvider),
		WithBeaconAttestationsSigner(beaconAttestationsSigner),
	)
	require.NoError(t, err)

	duty, err := attester.NewDuty(ctx,
		100,                                    // slot.
		1,                                      // committee at slot,
		[]phase0.ValidatorIndex{0},             // validator indices.
		[]phase0.CommitteeIndex{0},             // committee indices.
		[]uint64{0},                            // committee indices.
		map[phase0.CommitteeIndex]uint64{0: 0}, // committee lengths.
	)
	require.NoError(t, err)

	// Set up the data.
	s.attested[1] = make(map[phase0.ValidatorIndex]struct{})
	s.attested[2] = make(map[phase0.ValidatorIndex]struct{})
	s.attested[3] = make(map[phase0.ValidatorIndex]struct{})

	// Ensure the housekeeping removes an entry.
	require.Len(t, s.attested, 3)
	s.housekeepAttestedMap(ctx, duty)
	require.Len(t, s.attested, 2)

	// Change the attesting epoch to 0, ensure it still works.
	duty, err = attester.NewDuty(ctx,
		0,                                      // slot.
		1,                                      // committee at slot,
		[]phase0.ValidatorIndex{0},             // validator indices.
		[]phase0.CommitteeIndex{0},             // committee indices.
		[]uint64{0},                            // committee indices.
		map[phase0.CommitteeIndex]uint64{0: 0}, // committee lengths.
	)
	require.NoError(t, err)
	require.Len(t, s.attested, 2)
	s.housekeepAttestedMap(ctx, duty)
	require.Len(t, s.attested, 2)
}

func TestObtainAttestationData(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	attestationDataProvider := mock.NewAttestationDataProvider()
	attestationsSubmitter := mock.NewAttestationsSubmitter()
	beaconAttestationsSigner := mocksigner.New()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	validatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	prometheusMetrics, err := prometheusmetrics.New(ctx,
		prometheusmetrics.WithAddress(":12345"),
	)
	require.NoError(t, err)

	duty, err := attester.NewDuty(ctx,
		100,                                    // slot.
		1,                                      // committee at slot,
		[]phase0.ValidatorIndex{0},             // validator indices.
		[]phase0.CommitteeIndex{0},             // committee indices.
		[]uint64{0},                            // committee indices.
		map[phase0.CommitteeIndex]uint64{0: 0}, // committee lengths.
	)
	require.NoError(t, err)

	tests := []struct {
		name       string
		params     []Parameter
		err        string
		logEntries []map[string]any
	}{
		{
			name: "BadAttestationDataProvider",
			params: []Parameter{
				WithLogLevel(zerolog.TraceLevel),
				WithMonitor(prometheusMetrics),
				WithProcessConcurrency(1),
				WithChainTime(chainTime),
				WithSpecProvider(specProvider),
				WithAttestationDataProvider(mock.NewErroringAttestationDataProvider()),
				WithAttestationsSubmitter(attestationsSubmitter),
				WithValidatingAccountsProvider(validatingAccountsProvider),
				WithBeaconAttestationsSigner(beaconAttestationsSigner),
			},
			err: "failed to obtain attestation data: mock error",
		},
		{
			name: "Good",
			params: []Parameter{
				WithLogLevel(zerolog.TraceLevel),
				WithMonitor(prometheusMetrics),
				WithProcessConcurrency(1),
				WithChainTime(chainTime),
				WithSpecProvider(specProvider),
				WithAttestationDataProvider(attestationDataProvider),
				WithAttestationsSubmitter(attestationsSubmitter),
				WithValidatingAccountsProvider(validatingAccountsProvider),
				WithBeaconAttestationsSigner(beaconAttestationsSigner),
			},
			logEntries: []map[string]any{
				{
					"message": "Obtained attestation data",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			s, err := New(ctx, test.params...)
			require.NoError(t, err)
			attestationData, err := s.obtainAttestationData(ctx, duty)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, attestationData)
			}
			for i, entry := range test.logEntries {
				require.True(t, capture.HasLog(entry), "missing log entry %d", i)
			}
		})
	}
}

func TestFetchValidatorIndices(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	attestationDataProvider := mock.NewAttestationDataProvider()
	attestationsSubmitter := mock.NewAttestationsSubmitter()
	beaconAttestationsSigner := mocksigner.New()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	validatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	prometheusMetrics, err := prometheusmetrics.New(ctx,
		prometheusmetrics.WithAddress(":12345"),
	)
	require.NoError(t, err)

	duty, err := attester.NewDuty(ctx,
		100,                                 // slot.
		1,                                   // committee at slot,
		[]phase0.ValidatorIndex{1, 2, 3, 4}, // validator indices.
		[]phase0.CommitteeIndex{0, 0, 1, 1}, // committee indices.
		[]uint64{0, 1, 0, 1},                // committee indices.
		map[phase0.CommitteeIndex]uint64{0: 2, 1: 2}, // committee lengths.
	)
	require.NoError(t, err)

	tests := []struct {
		name       string
		attested   map[phase0.Epoch]map[phase0.ValidatorIndex]struct{}
		expected   []phase0.ValidatorIndex
		err        string
		logEntries []map[string]any
	}{
		{
			name:     "Simple",
			attested: make(map[phase0.Epoch]map[phase0.ValidatorIndex]struct{}),
			expected: []phase0.ValidatorIndex{1, 2, 3, 4},
			logEntries: []map[string]any{
				{
					"message": "Validating indices",
				},
			},
		},
		{
			name: "Duplicates",
			attested: map[phase0.Epoch]map[phase0.ValidatorIndex]struct{}{
				3: {
					1: struct{}{},
				},
			},
			expected: []phase0.ValidatorIndex{2, 3, 4},
			logEntries: []map[string]any{
				{
					"message":         "Validator already attested this epoch; not attesting again",
					"validator_index": uint64(1),
				},
				{
					"message": "Validating indices",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			s, err := New(ctx,
				WithLogLevel(zerolog.TraceLevel),
				WithMonitor(prometheusMetrics),
				WithProcessConcurrency(1),
				WithChainTime(chainTime),
				WithSpecProvider(specProvider),
				WithAttestationDataProvider(attestationDataProvider),
				WithAttestationsSubmitter(attestationsSubmitter),
				WithValidatingAccountsProvider(validatingAccountsProvider),
				WithBeaconAttestationsSigner(beaconAttestationsSigner),
			)
			require.NoError(t, err)

			s.attested = test.attested

			validatorIndices := s.fetchValidatorIndices(ctx, duty)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expected, validatorIndices)
			}
			for i, entry := range test.logEntries {
				require.True(t, capture.HasLog(entry), "missing log entry %d", i)
			}
		})
	}
}
