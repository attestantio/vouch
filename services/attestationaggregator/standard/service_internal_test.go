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

// testAggregateSlot is the slot carried by the attestations the tests supply.  Asserting on it
// proves the conversion carried the supplied attestation through rather than leaving it nil.
const testAggregateSlot = phase0.Slot(99)

// aggregateOf returns the aggregate attestation held by the arm the version names, so a
// conversion that populated the wrong arm - or left the aggregate nil - is visible to the caller.
func aggregateOf(t *testing.T, aggregateAndProof *spec.VersionedAggregateAndProof) any {
	t.Helper()

	switch aggregateAndProof.Version {
	case spec.DataVersionPhase0:
		return aggregateAndProof.Phase0.Aggregate
	case spec.DataVersionAltair:
		return aggregateAndProof.Altair.Aggregate
	case spec.DataVersionBellatrix:
		return aggregateAndProof.Bellatrix.Aggregate
	case spec.DataVersionCapella:
		return aggregateAndProof.Capella.Aggregate
	case spec.DataVersionDeneb:
		return aggregateAndProof.Deneb.Aggregate
	case spec.DataVersionElectra:
		return aggregateAndProof.Electra.Aggregate
	case spec.DataVersionFulu:
		return aggregateAndProof.Fulu.Aggregate
	case spec.DataVersionGloas:
		return aggregateAndProof.Gloas.Aggregate
	default:
		require.FailNow(t, "no aggregate for version", aggregateAndProof.Version.String())

		return nil
	}
}

func TestCreateVersionedAggregateAndProof(t *testing.T) {
	duty := &attestationaggregator.Duty{
		ValidatorIndex: phase0.ValidatorIndex(42),
		SlotSignature:  phase0.BLSSignature{1},
	}
	phase0Attestation := &phase0.Attestation{Data: &phase0.AttestationData{Slot: testAggregateSlot}}
	electraAttestation := &electra.Attestation{Data: &phase0.AttestationData{Slot: testAggregateSlot}}
	gloasAttestation := &gloas.Attestation{Data: &phase0.AttestationData{Slot: testAggregateSlot}}

	tests := []struct {
		name                 string
		versionedAttestation *spec.VersionedAttestation
		expectedAggregate    any
	}{
		{
			name: "Phase0",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionPhase0,
				Phase0:  phase0Attestation,
			},
			expectedAggregate: phase0Attestation,
		},
		{
			name: "Altair",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionAltair,
				Altair:  phase0Attestation,
			},
			expectedAggregate: phase0Attestation,
		},
		{
			name: "Bellatrix",
			versionedAttestation: &spec.VersionedAttestation{
				Version:   spec.DataVersionBellatrix,
				Bellatrix: phase0Attestation,
			},
			expectedAggregate: phase0Attestation,
		},
		{
			name: "Capella",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionCapella,
				Capella: phase0Attestation,
			},
			expectedAggregate: phase0Attestation,
		},
		{
			name: "Deneb",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionDeneb,
				Deneb:   phase0Attestation,
			},
			expectedAggregate: phase0Attestation,
		},
		{
			name: "Electra",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionElectra,
				Electra: electraAttestation,
			},
			expectedAggregate: electraAttestation,
		},
		{
			name: "Fulu",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionFulu,
				Fulu:    electraAttestation,
			},
			expectedAggregate: electraAttestation,
		},
		{
			name: "Gloas",
			versionedAttestation: &spec.VersionedAttestation{
				Version: spec.DataVersionGloas,
				Gloas:   gloasAttestation,
			},
			expectedAggregate: gloasAttestation,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := createVersionedAggregateAndProof(duty, test.versionedAttestation)
			require.NoError(t, err)
			require.Equal(t, test.versionedAttestation.Version, result.Version)
			aggregatorIndex, err := result.AggregatorIndex()
			require.NoError(t, err)
			require.Equal(t, duty.ValidatorIndex, aggregatorIndex)
			selectionProof, err := result.SelectionProof()
			require.NoError(t, err)
			require.Equal(t, duty.SlotSignature, selectionProof)
			require.Same(t, test.expectedAggregate, aggregateOf(t, result))
		})
	}
}

func TestCreateVersionedSignedAggregateAndProof(t *testing.T) {
	sig := phase0.BLSSignature{2}
	phase0AggregateAndProof := &phase0.AggregateAndProof{
		Aggregate: &phase0.Attestation{Data: &phase0.AttestationData{Slot: testAggregateSlot}},
	}
	electraAggregateAndProof := &electra.AggregateAndProof{
		Aggregate: &electra.Attestation{Data: &phase0.AttestationData{Slot: testAggregateSlot}},
	}
	gloasAggregateAndProof := &gloas.AggregateAndProof{
		Aggregate: &gloas.Attestation{Data: &phase0.AttestationData{Slot: testAggregateSlot}},
	}

	tests := []struct {
		name                       string
		versionedAggregateAndProof *spec.VersionedAggregateAndProof
	}{
		{
			name: "Phase0",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionPhase0,
				Phase0:  phase0AggregateAndProof,
			},
		},
		{
			name: "Altair",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionAltair,
				Altair:  phase0AggregateAndProof,
			},
		},
		{
			name: "Bellatrix",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version:   spec.DataVersionBellatrix,
				Bellatrix: phase0AggregateAndProof,
			},
		},
		{
			name: "Capella",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionCapella,
				Capella: phase0AggregateAndProof,
			},
		},
		{
			name: "Deneb",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionDeneb,
				Deneb:   phase0AggregateAndProof,
			},
		},
		{
			name: "Electra",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionElectra,
				Electra: electraAggregateAndProof,
			},
		},
		{
			name: "Fulu",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionFulu,
				Fulu:    electraAggregateAndProof,
			},
		},
		{
			name: "Gloas",
			versionedAggregateAndProof: &spec.VersionedAggregateAndProof{
				Version: spec.DataVersionGloas,
				Gloas:   gloasAggregateAndProof,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := createVersionedSignedAggregateAndProof(test.versionedAggregateAndProof, sig)
			require.NoError(t, err)
			require.Equal(t, test.versionedAggregateAndProof.Version, result.Version)
			signature, err := result.Signature()
			require.NoError(t, err)
			require.Equal(t, sig, signature)
			// Slot() reads through Message.Aggregate.Data without a nil guard, and the multinode
			// submitter calls it on every submission, so this proves the message was carried
			// through rather than left nil.
			slot, err := result.Slot()
			require.NoError(t, err)
			require.Equal(t, testAggregateSlot, slot)
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
		{name: "Unknown", version: spec.DataVersionUnknown, err: "unknown version"},
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
		{name: "Unknown", version: spec.DataVersionUnknown, err: "unknown version"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := createVersionedSignedAggregateAndProof(&spec.VersionedAggregateAndProof{Version: test.version}, phase0.BLSSignature{})
			require.Nil(t, result)
			require.EqualError(t, err, test.err)
		})
	}
}
