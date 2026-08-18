// Copyright © 2026 Attestant Limited.
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
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/stretchr/testify/require"
)

func TestCreateVersionedAggregateAndProofGloas(t *testing.T) {
	duty := &attestationaggregator.Duty{
		ValidatorIndex: phase0.ValidatorIndex(42),
		SlotSignature:  phase0.BLSSignature{1},
	}
	attestation := &gloas.Attestation{}

	tests := []struct {
		name                 string
		versionedAttestation *spec.VersionedAttestation
		err                  string
	}{
		{
			name: "Valid",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionGloas,
				Gloas:   attestation,
			},
		},
		{
			name: "MissingArm",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionGloas,
			},
			err: "no gloas attestation",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := createVersionedAggregateAndProof(duty, test.versionedAttestation)
			if test.err != "" {
				require.Nil(t, result)
				require.EqualError(t, err, test.err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, spec.DataVersionGloas, result.Version)
			require.NotNil(t, result.Gloas)
			require.Same(t, attestation, result.Gloas.Aggregate)
			require.Equal(t, duty.ValidatorIndex, result.Gloas.AggregatorIndex)
			require.Equal(t, duty.SlotSignature, result.Gloas.SelectionProof)
		})
	}
}

func TestCreateVersionedSignedAggregateAndProofGloas(t *testing.T) {
	aggregateAndProof := &gloas.AggregateAndProof{}
	sig := phase0.BLSSignature{2}

	tests := []struct {
		name                       string
		versionedAggregateAndProof *spec.VersionedAggregateAndProof
		err                        string
	}{
		{
			name: "Valid",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionGloas,
				Gloas:   aggregateAndProof,
			},
		},
		{
			name: "MissingArm",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionGloas,
			},
			err: "no gloas aggregate and proof",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := createVersionedSignedAggregateAndProof(test.versionedAggregateAndProof, sig)
			if test.err != "" {
				require.Nil(t, result)
				require.EqualError(t, err, test.err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, spec.DataVersionGloas, result.Version)
			require.NotNil(t, result.Gloas)
			require.Same(t, aggregateAndProof, result.Gloas.Message)
			require.Equal(t, sig, result.Gloas.Signature)
		})
	}
}
