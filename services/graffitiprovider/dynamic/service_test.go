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

package dynamic_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/attestantio/vouch/services/graffitiprovider/dynamic"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/wealdtech/go-majordomo"
	directconfidant "github.com/wealdtech/go-majordomo/confidants/direct"
	fileconfidant "github.com/wealdtech/go-majordomo/confidants/file"
	standardmajordomo "github.com/wealdtech/go-majordomo/standard"
)

func TestService(t *testing.T) {
	ctx := context.Background()
	majordomoSvc, err := standardmajordomo.New(ctx)
	require.NoError(t, err)
	directConfidant, err := directconfidant.New(ctx)
	require.NoError(t, err)
	err = majordomoSvc.RegisterConfidant(ctx, directConfidant)
	require.NoError(t, err)

	tests := []struct {
		name      string
		majordomo majordomo.Service
		location  string
		err       string
	}{
		{
			name:     "MajordomoMissing",
			location: "direct://static",
			err:      "problem with parameters: no majordomo specified",
		},
		{
			name:      "LocationMissing",
			majordomo: majordomoSvc,
			err:       "problem with parameters: no location specified",
		},
		{
			name:      "Good",
			majordomo: majordomoSvc,
			location:  "direct://static",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := dynamic.New(ctx,
				dynamic.WithLogLevel(zerolog.Disabled),
				dynamic.WithMajordomo(test.majordomo),
				dynamic.WithLocation(test.location))

			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestReplacement(t *testing.T) {
	ctx := context.Background()
	majordomoSvc, err := standardmajordomo.New(ctx)
	require.NoError(t, err)
	directConfidant, err := directconfidant.New(ctx)
	require.NoError(t, err)
	err = majordomoSvc.RegisterConfidant(ctx, directConfidant)
	require.NoError(t, err)

	tests := []struct {
		name              string
		location          string
		expectedGraffitis []string
	}{
		{
			name:     "Static",
			location: "direct:///test",
			expectedGraffitis: []string{
				"test",
			},
		},
		{
			name:     "SlotVariable",
			location: "direct:///{{SLOT}}",
			expectedGraffitis: []string{
				"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15",
			},
		},
		{
			name:     "DoubleSlotVariable",
			location: "direct:///{{SLOT}} and {{SLOT}}",
			expectedGraffitis: []string{
				"0 and 0", "1 and 1", "2 and 2", "3 and 3", "4 and 4", "5 and 5", "6 and 6", "7 and 7", "8 and 8",
				"9 and 9", "10 and 10", "11 and 11", "12 and 12", "13 and 13", "14 and 14", "15 and 15",
			},
		},
		{
			name:     "ValidatorIndexVariable",
			location: "direct:///{{VALIDATORINDEX}}",
			expectedGraffitis: []string{
				"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15",
			},
		},
		{
			name:     "DoubleValidatorIndexVariable",
			location: "direct:///{{VALIDATORINDEX}} and {{VALIDATORINDEX}}",
			expectedGraffitis: []string{
				"0 and 0", "1 and 1", "2 and 2", "3 and 3", "4 and 4", "5 and 5", "6 and 6", "7 and 7", "8 and 8",
				"9 and 9", "10 and 10", "11 and 11", "12 and 12", "13 and 13", "14 and 14", "15 and 15",
			},
		},
		{
			name:     "ValidatorIndexAndSlotVariables",
			location: "direct:///{{VALIDATORINDEX}} and {{SLOT}}",
			expectedGraffitis: []string{
				"0 and 0", "0 and 1", "0 and 2", "0 and 3", "0 and 4", "0 and 5", "0 and 6", "0 and 7", "0 and 8",
				"0 and 9", "0 and 10", "0 and 11", "0 and 12", "0 and 13", "0 and 14", "0 and 15",
				"1 and 0", "1 and 1", "1 and 2", "1 and 3", "1 and 4", "1 and 5", "1 and 6", "1 and 7", "1 and 8",
				"1 and 9", "1 and 10", "1 and 11", "1 and 12", "1 and 13", "1 and 14", "1 and 15",
				"2 and 0", "2 and 1", "2 and 2", "2 and 3", "2 and 4", "2 and 5", "2 and 6", "2 and 7", "2 and 8",
				"2 and 9", "2 and 10", "2 and 11", "2 and 12", "2 and 13", "2 and 14", "2 and 15",
				"3 and 0", "3 and 1", "3 and 2", "3 and 3", "3 and 4", "3 and 5", "3 and 6", "3 and 7", "3 and 8",
				"3 and 9", "3 and 10", "3 and 11", "3 and 12", "3 and 13", "3 and 14", "3 and 15",
				"4 and 0", "4 and 1", "4 and 2", "4 and 3", "4 and 4", "4 and 5", "4 and 6", "4 and 7", "4 and 8",
				"4 and 9", "4 and 10", "4 and 11", "4 and 12", "4 and 13", "4 and 14", "4 and 15",
				"5 and 0", "5 and 1", "5 and 2", "5 and 3", "5 and 4", "5 and 5", "5 and 6", "5 and 7", "5 and 8",
				"5 and 9", "5 and 10", "5 and 11", "5 and 12", "5 and 13", "5 and 14", "5 and 15",
				"6 and 0", "6 and 1", "6 and 2", "6 and 3", "6 and 4", "6 and 5", "6 and 6", "6 and 7", "6 and 8",
				"6 and 9", "6 and 10", "6 and 11", "6 and 12", "6 and 13", "6 and 14", "6 and 15",
				"7 and 0", "7 and 1", "7 and 2", "7 and 3", "7 and 4", "7 and 5", "7 and 6", "7 and 7", "7 and 8",
				"7 and 9", "7 and 10", "7 and 11", "7 and 12", "7 and 13", "7 and 14", "7 and 15",
				"8 and 0", "8 and 1", "8 and 2", "8 and 3", "8 and 4", "8 and 5", "8 and 6", "8 and 7", "8 and 8",
				"8 and 9", "8 and 10", "8 and 11", "8 and 12", "8 and 13", "8 and 14", "8 and 15",
				"9 and 0", "9 and 1", "9 and 2", "9 and 3", "9 and 4", "9 and 5", "9 and 6", "9 and 7", "9 and 8",
				"9 and 9", "9 and 10", "9 and 11", "9 and 12", "9 and 13", "9 and 14", "9 and 15",
				"10 and 0", "10 and 1", "10 and 2", "10 and 3", "10 and 4", "10 and 5", "10 and 6", "10 and 7", "10 and 8",
				"10 and 9", "10 and 10", "10 and 11", "10 and 12", "10 and 13", "10 and 14", "10 and 15",
				"11 and 0", "11 and 1", "11 and 2", "11 and 3", "11 and 4", "11 and 5", "11 and 6", "11 and 7", "11 and 8",
				"11 and 9", "11 and 10", "11 and 11", "11 and 12", "11 and 13", "11 and 14", "11 and 15",
				"12 and 0", "12 and 1", "12 and 2", "12 and 3", "12 and 4", "12 and 5", "12 and 6", "12 and 7", "12 and 8",
				"12 and 9", "12 and 10", "12 and 11", "12 and 12", "12 and 13", "12 and 14", "12 and 15",
				"13 and 0", "13 and 1", "13 and 2", "13 and 3", "13 and 4", "13 and 5", "13 and 6", "13 and 7", "13 and 8",
				"13 and 9", "13 and 10", "13 and 11", "13 and 12", "13 and 13", "13 and 14", "13 and 15",
				"14 and 0", "14 and 1", "14 and 2", "14 and 3", "14 and 4", "14 and 5", "14 and 6", "14 and 7", "14 and 8",
				"14 and 9", "14 and 10", "14 and 11", "14 and 12", "14 and 13", "14 and 14", "14 and 15",
				"15 and 0", "15 and 1", "15 and 2", "15 and 3", "15 and 4", "15 and 5", "15 and 6", "15 and 7", "15 and 8",
				"15 and 9", "15 and 10", "15 and 11", "15 and 12", "15 and 13", "15 and 14", "15 and 15",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectedGraffitis := make(map[string]bool)
			for _, expectedGraffiti := range test.expectedGraffitis {
				expectedGraffitis[expectedGraffiti] = true
			}
			svc, err := dynamic.New(ctx,
				dynamic.WithLogLevel(zerolog.Disabled),
				dynamic.WithMajordomo(majordomoSvc),
				dynamic.WithLocation(test.location))
			require.NoError(t, err)
			for validatorIndex := uint64(0); validatorIndex < 16; validatorIndex++ {
				for slot := uint64(0); slot < 16; slot++ {
					graffiti, err := svc.Graffiti(ctx, slot, validatorIndex)
					require.NoError(t, err)
					delete(expectedGraffitis, string(graffiti))
				}
			}
			require.Empty(t, expectedGraffitis)
		})
	}
}

func TestMultiline(t *testing.T) {
	ctx := context.Background()
	majordomoSvc, err := standardmajordomo.New(ctx)
	require.NoError(t, err)
	fileConfidant, err := fileconfidant.New(ctx)
	require.NoError(t, err)
	err = majordomoSvc.RegisterConfidant(ctx, fileConfidant)
	require.NoError(t, err)

	tmpDir, err := ioutil.TempDir(os.TempDir(), "TestMultiline")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name              string
		location          string
		content           string
		expectedGraffitis map[string]bool
	}{
		{
			name:              "NoLines",
			location:          fmt.Sprintf("file://%s/NoLines", tmpDir),
			content:           "",
			expectedGraffitis: map[string]bool{"": true},
		},
		{
			name:     "SingleLine",
			location: fmt.Sprintf("file://%s/SingleLine", tmpDir),
			content:  "Single line\r\n",
			expectedGraffitis: map[string]bool{
				"Single line": true,
			},
		},
		{
			name:     "MultiLine",
			location: fmt.Sprintf("file://%s/MultiLine", tmpDir),
			content:  "Line 1\r\nLine 2",
			expectedGraffitis: map[string]bool{
				"Line 1": true,
				"Line 2": true,
			},
		},
		{
			name:     "Blanks",
			location: fmt.Sprintf("file://%s/Blanks", tmpDir),
			content:  "\n\r\n\r\nThe line\r\n\n\n\r\r\n",
			expectedGraffitis: map[string]bool{
				"The line": true,
			},
		},
		{
			name:     "Template",
			location: fmt.Sprintf("file://%s/Template", tmpDir),
			content:  "Graffiti for validator {{VALIDATORINDEX}}\nGraffiti for slot {{SLOT}}",
			expectedGraffitis: map[string]bool{
				"Graffiti for validator 0":  true,
				"Graffiti for validator 1":  true,
				"Graffiti for validator 2":  true,
				"Graffiti for validator 3":  true,
				"Graffiti for validator 4":  true,
				"Graffiti for validator 5":  true,
				"Graffiti for validator 6":  true,
				"Graffiti for validator 7":  true,
				"Graffiti for validator 8":  true,
				"Graffiti for validator 9":  true,
				"Graffiti for validator 10": true,
				"Graffiti for validator 11": true,
				"Graffiti for validator 12": true,
				"Graffiti for validator 13": true,
				"Graffiti for validator 14": true,
				"Graffiti for validator 15": true,
				"Graffiti for slot 0":       true,
				"Graffiti for slot 1":       true,
				"Graffiti for slot 2":       true,
				"Graffiti for slot 3":       true,
				"Graffiti for slot 4":       true,
				"Graffiti for slot 5":       true,
				"Graffiti for slot 6":       true,
				"Graffiti for slot 7":       true,
				"Graffiti for slot 8":       true,
				"Graffiti for slot 9":       true,
				"Graffiti for slot 10":      true,
				"Graffiti for slot 11":      true,
				"Graffiti for slot 12":      true,
				"Graffiti for slot 13":      true,
				"Graffiti for slot 14":      true,
				"Graffiti for slot 15":      true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			obtainedGraffitis := make(map[string]bool)
			for expectedGraffiti := range test.expectedGraffitis {
				obtainedGraffitis[expectedGraffiti] = true
			}
			err = ioutil.WriteFile(filepath.Join(tmpDir, test.name), []byte(test.content), 0600)
			require.NoError(t, err)
			svc, err := dynamic.New(ctx,
				dynamic.WithLogLevel(zerolog.Disabled),
				dynamic.WithMajordomo(majordomoSvc),
				dynamic.WithLocation(test.location))
			require.NoError(t, err)
			for validatorIndex := uint64(0); validatorIndex < 16; validatorIndex++ {
				for slot := uint64(0); slot < 16; slot++ {
					graffiti, err := svc.Graffiti(ctx, slot, validatorIndex)
					require.NoError(t, err)
					require.Contains(t, test.expectedGraffitis, string(graffiti))
					delete(obtainedGraffitis, string(graffiti))
				}
			}
			require.Empty(t, obtainedGraffitis)
		})
	}
}
