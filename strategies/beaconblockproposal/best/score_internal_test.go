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

package best

import (
	"context"
	"testing"

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/testutil"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/assert"
)

func aggregationBits(set uint64, total uint64) bitfield.Bitlist {
	bits := bitfield.NewBitlist(total)
	for i := uint64(0); i < set; i++ {
		bits.SetBitAt(i, true)
	}
	return bits
}

func specificAggregationBits(set []uint64, total uint64) bitfield.Bitlist {
	bits := bitfield.NewBitlist(total)
	for _, pos := range set {
		bits.SetBitAt(pos, true)
	}
	return bits
}

func TestScore(t *testing.T) {
	tests := []struct {
		name       string
		block      *spec.BeaconBlock
		parentSlot spec.Slot
		score      float64
		err        string
	}{
		{
			name:       "Nil",
			parentSlot: 1,
			score:      0,
		},
		{
			name:       "Empty",
			block:      &spec.BeaconBlock{},
			parentSlot: 1,
			score:      0,
		},
		{
			name: "SingleAttestation",
			block: &spec.BeaconBlock{
				Slot: 12345,
				Body: &spec.BeaconBlockBody{
					Attestations: []*spec.Attestation{
						{
							AggregationBits: aggregationBits(1, 128),
							Data: &spec.AttestationData{
								Slot: 12344,
							},
						},
					},
				},
			},
			parentSlot: 12344,
			score:      1,
		},
		{
			name: "SingleAttestationParentRootDistance2",
			block: &spec.BeaconBlock{
				Slot: 12345,
				Body: &spec.BeaconBlockBody{
					Attestations: []*spec.Attestation{
						{
							AggregationBits: aggregationBits(1, 128),
							Data: &spec.AttestationData{
								Slot: 12344,
							},
						},
					},
				},
			},
			parentSlot: 12343,
			score:      0.5,
		},
		{
			name: "SingleAttestationDistance2",
			block: &spec.BeaconBlock{
				Slot: 12345,
				Body: &spec.BeaconBlockBody{
					Attestations: []*spec.Attestation{
						{
							AggregationBits: aggregationBits(1, 128),
							Data: &spec.AttestationData{
								Slot: 12343,
							},
						},
					},
				},
			},
			parentSlot: 12344,
			score:      0.875,
		},
		{
			name: "TwoAttestations",
			block: &spec.BeaconBlock{
				Slot: 12345,
				Body: &spec.BeaconBlockBody{
					Attestations: []*spec.Attestation{
						{
							AggregationBits: aggregationBits(2, 128),
							Data: &spec.AttestationData{
								Slot: 12344,
							},
						},
						{
							AggregationBits: aggregationBits(1, 128),
							Data: &spec.AttestationData{
								Slot: 12341,
							},
						},
					},
				},
			},
			parentSlot: 12344,
			score:      2.8125,
		},
		{
			name: "AttesterSlashing",
			block: &spec.BeaconBlock{
				Slot: 12345,
				Body: &spec.BeaconBlockBody{
					Attestations: []*spec.Attestation{
						{
							AggregationBits: aggregationBits(50, 128),
							Data: &spec.AttestationData{
								Slot: 12344,
							},
						},
					},
					AttesterSlashings: []*spec.AttesterSlashing{
						{
							Attestation1: &spec.IndexedAttestation{
								AttestingIndices: []uint64{1, 2, 3},
							},
							Attestation2: &spec.IndexedAttestation{
								AttestingIndices: []uint64{2, 3, 4},
							},
						},
					},
				},
			},
			parentSlot: 12344,
			score:      1450,
		},
		{
			name: "DuplicateAttestations",
			block: &spec.BeaconBlock{
				Slot: 12345,
				Body: &spec.BeaconBlockBody{
					Attestations: []*spec.Attestation{
						{
							AggregationBits: specificAggregationBits([]uint64{1, 2, 3}, 128),
							Data: &spec.AttestationData{
								Slot: 12344,
							},
						},
						{
							AggregationBits: specificAggregationBits([]uint64{2, 3, 4}, 128),
							Data: &spec.AttestationData{
								Slot: 12344,
							},
						},
					},
				},
			},
			parentSlot: 12344,
			score:      4,
		},
		{
			name: "Full",
			block: &spec.BeaconBlock{
				Slot: 12345,
				Body: &spec.BeaconBlockBody{
					Attestations: []*spec.Attestation{
						{
							AggregationBits: aggregationBits(50, 128),
							Data: &spec.AttestationData{
								Slot: 12344,
							},
						},
					},
					AttesterSlashings: []*spec.AttesterSlashing{
						{
							Attestation1: &spec.IndexedAttestation{
								AttestingIndices: []uint64{1, 2, 3},
							},
							Attestation2: &spec.IndexedAttestation{
								AttestingIndices: []uint64{2, 3, 4},
							},
						},
					},
					ProposerSlashings: []*spec.ProposerSlashing{
						{
							SignedHeader1: &spec.SignedBeaconBlockHeader{
								Message: &spec.BeaconBlockHeader{
									Slot:          10,
									ProposerIndex: 1,
									ParentRoot:    testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
									StateRoot:     testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
									BodyRoot:      testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
								},
								Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
							},
							SignedHeader2: &spec.SignedBeaconBlockHeader{
								Message: &spec.BeaconBlockHeader{
									Slot:          10,
									ProposerIndex: 1,
									ParentRoot:    testutil.HexToRoot("0x0404040404040404040404040404040404040404040404040404040404040404"),
									StateRoot:     testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
									BodyRoot:      testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
								},
								Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
							},
						},
					},
				},
			},
			parentSlot: 12344,
			score:      2150,
		},
		{
			name: "FullParentRootDistance2",
			block: &spec.BeaconBlock{
				Slot: 12345,
				Body: &spec.BeaconBlockBody{
					Attestations: []*spec.Attestation{
						{
							AggregationBits: aggregationBits(50, 128),
							Data: &spec.AttestationData{
								Slot: 12344,
							},
						},
					},
					AttesterSlashings: []*spec.AttesterSlashing{
						{
							Attestation1: &spec.IndexedAttestation{
								AttestingIndices: []uint64{1, 2, 3},
							},
							Attestation2: &spec.IndexedAttestation{
								AttestingIndices: []uint64{2, 3, 4},
							},
						},
					},
					ProposerSlashings: []*spec.ProposerSlashing{
						{
							SignedHeader1: &spec.SignedBeaconBlockHeader{
								Message: &spec.BeaconBlockHeader{
									Slot:          10,
									ProposerIndex: 1,
									ParentRoot:    testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
									StateRoot:     testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
									BodyRoot:      testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
								},
								Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
							},
							SignedHeader2: &spec.SignedBeaconBlockHeader{
								Message: &spec.BeaconBlockHeader{
									Slot:          10,
									ProposerIndex: 1,
									ParentRoot:    testutil.HexToRoot("0x0404040404040404040404040404040404040404040404040404040404040404"),
									StateRoot:     testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
									BodyRoot:      testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
								},
								Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
							},
						},
					},
				},
			},
			parentSlot: 12343,
			score:      1075,
		},
		{
			name: "FullParentRootDistance4",
			block: &spec.BeaconBlock{
				Slot: 12345,
				Body: &spec.BeaconBlockBody{
					Attestations: []*spec.Attestation{
						{
							AggregationBits: aggregationBits(50, 128),
							Data: &spec.AttestationData{
								Slot: 12344,
							},
						},
					},
					AttesterSlashings: []*spec.AttesterSlashing{
						{
							Attestation1: &spec.IndexedAttestation{
								AttestingIndices: []uint64{1, 2, 3},
							},
							Attestation2: &spec.IndexedAttestation{
								AttestingIndices: []uint64{2, 3, 4},
							},
						},
					},
					ProposerSlashings: []*spec.ProposerSlashing{
						{
							SignedHeader1: &spec.SignedBeaconBlockHeader{
								Message: &spec.BeaconBlockHeader{
									Slot:          10,
									ProposerIndex: 1,
									ParentRoot:    testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
									StateRoot:     testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
									BodyRoot:      testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
								},
								Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
							},
							SignedHeader2: &spec.SignedBeaconBlockHeader{
								Message: &spec.BeaconBlockHeader{
									Slot:          10,
									ProposerIndex: 1,
									ParentRoot:    testutil.HexToRoot("0x0404040404040404040404040404040404040404040404040404040404040404"),
									StateRoot:     testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
									BodyRoot:      testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
								},
								Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
							},
						},
					},
				},
			},
			parentSlot: 12341,
			score:      537.5,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			score := scoreBeaconBlockProposal(context.Background(), test.name, test.parentSlot, test.block)
			assert.Equal(t, test.score, score)
		})
	}
}
