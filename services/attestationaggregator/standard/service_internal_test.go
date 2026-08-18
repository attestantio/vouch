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
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/attestationaggregator"
	"github.com/stretchr/testify/require"
)

func TestCreateVersionedAggregateAndProof(t *testing.T) {
	duty := &attestationaggregator.Duty{
		ValidatorIndex: phase0.ValidatorIndex(42),
		SlotSignature:  phase0.BLSSignature{1},
	}

	tests := []struct {
		name                 string
		versionedAttestation *spec.VersionedAttestation
		err                  string
	}{
		{
			name: "Phase0",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionPhase0,
				Phase0:  &phase0.Attestation{},
			},
		},
		{
			name: "Altair",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionAltair,
				Altair:  &phase0.Attestation{},
			},
		},
		{
			name: "Bellatrix",
			versionedAttestation: &spec.VersionedAttestation{
				Version:   spec.DataVersionBellatrix,
				Bellatrix: &phase0.Attestation{},
			},
		},
		{
			name: "Capella",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionCapella,
				Capella: &phase0.Attestation{},
			},
		},
		{
			name: "Deneb",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionDeneb,
				Deneb:   &phase0.Attestation{},
			},
		},
		{
			name: "Electra",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionElectra,
				Electra: &electra.Attestation{},
			},
		},
		{
			name: "Fulu",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionFulu,
				Fulu:    &electra.Attestation{},
			},
		},
		{
			name: "Gloas",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionGloas,
				Gloas:   &gloas.Attestation{},
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
			require.Equal(t, test.versionedAttestation.Version, result.Version)
			aggregatorIndex, err := result.AggregatorIndex()
			require.NoError(t, err)
			require.Equal(t, duty.ValidatorIndex, aggregatorIndex)
			selectionProof, err := result.SelectionProof()
			require.NoError(t, err)
			require.Equal(t, duty.SlotSignature, selectionProof)
		})
	}
}

func TestCreateVersionedSignedAggregateAndProof(t *testing.T) {
	sig := phase0.BLSSignature{2}

	tests := []struct {
		name                       string
		versionedAggregateAndProof *spec.VersionedAggregateAndProof
		err                        string
	}{
		{
			name: "Phase0",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionPhase0,
				Phase0:  &phase0.AggregateAndProof{},
			},
		},
		{
			name: "Altair",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionAltair,
				Altair:  &phase0.AggregateAndProof{},
			},
		},
		{
			name: "Bellatrix",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version:   spec.DataVersionBellatrix,
				Bellatrix: &phase0.AggregateAndProof{},
			},
		},
		{
			name: "Capella",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionCapella,
				Capella: &phase0.AggregateAndProof{},
			},
		},
		{
			name: "Deneb",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionDeneb,
				Deneb:   &phase0.AggregateAndProof{},
			},
		},
		{
			name: "Electra",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionElectra,
				Electra: &electra.AggregateAndProof{},
			},
		},
		{
			name: "Fulu",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionFulu,
				Fulu:    &electra.AggregateAndProof{},
			},
		},
		{
			name: "Gloas",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionGloas,
				Gloas:   &gloas.AggregateAndProof{},
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
			require.Equal(t, test.versionedAggregateAndProof.Version, result.Version)
			signature, err := result.Signature()
			require.NoError(t, err)
			require.Equal(t, sig, signature)
		})
	}
}

func TestCreateVersionedAggregateAndProofRejectsMissingArms(t *testing.T) {
	duty := &attestationaggregator.Duty{}
	tests := []struct {
		name    string
		version spec.DataVersion
		err     string
	}{
		{name: "Phase0", version: spec.DataVersionPhase0, err: "no phase0 attestation"},
		{name: "Altair", version: spec.DataVersionAltair, err: "no altair attestation"},
		{name: "Bellatrix", version: spec.DataVersionBellatrix, err: "no bellatrix attestation"},
		{name: "Capella", version: spec.DataVersionCapella, err: "no capella attestation"},
		{name: "Deneb", version: spec.DataVersionDeneb, err: "no deneb attestation"},
		{name: "Electra", version: spec.DataVersionElectra, err: "no electra attestation"},
		{name: "Fulu", version: spec.DataVersionFulu, err: "no fulu attestation"},
		{name: "Gloas", version: spec.DataVersionGloas, err: "no gloas attestation"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := createVersionedAggregateAndProof(duty, &spec.VersionedAttestation{Version: test.version})
			require.Nil(t, result)
			require.EqualError(t, err, test.err)
		})
	}
}

func TestCreateVersionedSignedAggregateAndProofRejectsMissingArms(t *testing.T) {
	tests := []struct {
		name    string
		version spec.DataVersion
		err     string
	}{
		{name: "Phase0", version: spec.DataVersionPhase0, err: "no phase0 aggregate and proof"},
		{name: "Altair", version: spec.DataVersionAltair, err: "no altair aggregate and proof"},
		{name: "Bellatrix", version: spec.DataVersionBellatrix, err: "no bellatrix aggregate and proof"},
		{name: "Capella", version: spec.DataVersionCapella, err: "no capella aggregate and proof"},
		{name: "Deneb", version: spec.DataVersionDeneb, err: "no deneb aggregate and proof"},
		{name: "Electra", version: spec.DataVersionElectra, err: "no electra aggregate and proof"},
		{name: "Fulu", version: spec.DataVersionFulu, err: "no fulu aggregate and proof"},
		{name: "Gloas", version: spec.DataVersionGloas, err: "no gloas aggregate and proof"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := createVersionedSignedAggregateAndProof(&spec.VersionedAggregateAndProof{Version: test.version}, phase0.BLSSignature{})
			require.Nil(t, result)
			require.EqualError(t, err, test.err)
		})
	}
}
