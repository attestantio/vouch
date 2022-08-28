// Copyright © 2020 - 2022 Attestant Limited.
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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/testutil"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bitList(set uint64, total uint64) bitfield.Bitlist {
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
		name        string
		priorBlocks map[phase0.Root]*priorBlockVotes
		block       *spec.VersionedBeaconBlock
		score       float64
		err         string
	}{
		{
			name:  "Nil",
			score: 0,
		},
		{
			name:  "Empty",
			block: &spec.VersionedBeaconBlock{},
			score: 0,
		},
		{
			name: "SingleAttestation",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionPhase0,
				Phase0: &phase0.BeaconBlock{
					Slot:       12346,
					ParentRoot: testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
					Body: &phase0.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot: 12345,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										Epoch: 385,
									},
								},
							},
						},
					},
				},
			},
			score: 1,
		},
		{
			name: "SingleAttestationParentRootDistance2",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionPhase0,
				Phase0: &phase0.BeaconBlock{
					Slot:       12346,
					ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
					Body: &phase0.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot: 12345,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										Epoch: 385,
									},
								},
							},
						},
					},
				},
			},
			score: 0.5,
		},
		{
			name: "SingleAttestationDistance2",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionPhase0,
				Phase0: &phase0.BeaconBlock{
					Slot:       12345,
					ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
					Body: &phase0.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot: 12343,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										Epoch: 385,
									},
								},
							},
						},
					},
				},
			},
			score: 0.875,
		},
		{
			name: "TwoAttestations",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionPhase0,
				Phase0: &phase0.BeaconBlock{
					Slot:       12345,
					ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
					Body: &phase0.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(2, 128),
								Data: &phase0.AttestationData{
									Slot: 12344,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										Epoch: 385,
									},
								},
							},
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot: 12341,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
										Epoch: 385,
									},
								},
							},
						},
					},
				},
			},
			score: 2.8125,
		},
		{
			name: "AttesterSlashing",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionPhase0,
				Phase0: &phase0.BeaconBlock{
					Slot:       12345,
					ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
					Body: &phase0.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(50, 128),
								Data: &phase0.AttestationData{
									Slot: 12344,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										Epoch: 385,
									},
								},
							},
						},
						AttesterSlashings: []*phase0.AttesterSlashing{
							{
								Attestation1: &phase0.IndexedAttestation{
									AttestingIndices: []uint64{1, 2, 3},
								},
								Attestation2: &phase0.IndexedAttestation{
									AttestingIndices: []uint64{2, 3, 4},
								},
							},
						},
					},
				},
			},
			score: 5450,
		},
		{
			name: "DuplicateAttestations",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionPhase0,
				Phase0: &phase0.BeaconBlock{
					Slot:       12345,
					ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
					Body: &phase0.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: specificAggregationBits([]uint64{1, 2, 3}, 128),
								Data: &phase0.AttestationData{
									Slot: 12344,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										Epoch: 385,
									},
								},
							},
							{
								AggregationBits: specificAggregationBits([]uint64{2, 3, 4}, 128),
								Data: &phase0.AttestationData{
									Slot: 12344,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										Epoch: 385,
									},
								},
							},
						},
					},
				},
			},
			score: 4,
		},
		{
			name: "Full",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionPhase0,
				Phase0: &phase0.BeaconBlock{
					Slot:       12345,
					ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
					Body: &phase0.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(50, 128),
								Data: &phase0.AttestationData{
									Slot: 12344,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										Epoch: 385,
									},
								},
							},
						},
						AttesterSlashings: []*phase0.AttesterSlashing{
							{
								Attestation1: &phase0.IndexedAttestation{
									AttestingIndices: []uint64{1, 2, 3},
								},
								Attestation2: &phase0.IndexedAttestation{
									AttestingIndices: []uint64{2, 3, 4},
								},
							},
						},
						ProposerSlashings: []*phase0.ProposerSlashing{
							{
								SignedHeader1: &phase0.SignedBeaconBlockHeader{
									Message: &phase0.BeaconBlockHeader{
										Slot:          10,
										ProposerIndex: 1,
										ParentRoot:    testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										StateRoot:     testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
										BodyRoot:      testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
									},
									Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
								},
								SignedHeader2: &phase0.SignedBeaconBlockHeader{
									Message: &phase0.BeaconBlockHeader{
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
			},
			score: 8150,
		},
		{
			name: "FullParentRootDistance2",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionPhase0,
				Phase0: &phase0.BeaconBlock{
					Slot:       12346,
					ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
					Body: &phase0.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(50, 128),
								Data: &phase0.AttestationData{
									Slot: 12345,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										Epoch: 385,
									},
								},
							},
						},
						AttesterSlashings: []*phase0.AttesterSlashing{
							{
								Attestation1: &phase0.IndexedAttestation{
									AttestingIndices: []uint64{1, 2, 3},
								},
								Attestation2: &phase0.IndexedAttestation{
									AttestingIndices: []uint64{2, 3, 4},
								},
							},
						},
						ProposerSlashings: []*phase0.ProposerSlashing{
							{
								SignedHeader1: &phase0.SignedBeaconBlockHeader{
									Message: &phase0.BeaconBlockHeader{
										Slot:          10,
										ProposerIndex: 1,
										ParentRoot:    testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										StateRoot:     testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
										BodyRoot:      testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
									},
									Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
								},
								SignedHeader2: &phase0.SignedBeaconBlockHeader{
									Message: &phase0.BeaconBlockHeader{
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
			},
			score: 8125,
		},
		{
			name: "FullParentRootDistance4",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionPhase0,
				Phase0: &phase0.BeaconBlock{
					Slot:       12348,
					ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
					Body: &phase0.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(50, 128),
								Data: &phase0.AttestationData{
									Slot: 12347,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										Epoch: 385,
									},
								},
							},
						},
						AttesterSlashings: []*phase0.AttesterSlashing{
							{
								Attestation1: &phase0.IndexedAttestation{
									AttestingIndices: []uint64{1, 2, 3},
								},
								Attestation2: &phase0.IndexedAttestation{
									AttestingIndices: []uint64{2, 3, 4},
								},
							},
						},
						ProposerSlashings: []*phase0.ProposerSlashing{
							{
								SignedHeader1: &phase0.SignedBeaconBlockHeader{
									Message: &phase0.BeaconBlockHeader{
										Slot:          10,
										ProposerIndex: 1,
										ParentRoot:    testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										StateRoot:     testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
										BodyRoot:      testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
									},
									Signature: testutil.HexToSignature("0x040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"),
								},
								SignedHeader2: &phase0.SignedBeaconBlockHeader{
									Message: &phase0.BeaconBlockHeader{
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
			},
			score: 8112.5,
		},
		{
			name: "AltairSingleAttestationDistance1",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.BeaconBlock{
					Slot:       12346,
					ParentRoot: testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
					Body: &altair.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot:            12345,
									BeaconBlockRoot: testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										Epoch: 385,
									},
								},
							},
						},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits: bitfield.NewBitvector512(),
						},
					},
				},
			},
			score: 0.84375,
		},
		{
			name: "AltairSingleAttestationDistance1IncorrectHead",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.BeaconBlock{
					Slot:       12346,
					ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
					Body: &altair.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot:            12345,
									BeaconBlockRoot: testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
										Epoch: 385,
									},
								},
							},
						},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits: bitfield.NewBitvector512(),
						},
					},
				},
			},
			score: 0.625,
		},
		{
			name: "AltairSingleAttestationDistance2",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.BeaconBlock{
					Slot:       12346,
					ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
					Body: &altair.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot: 12343,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"),
										Epoch: 385,
									},
								},
							},
						},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits: bitfield.NewBitvector512(),
						},
					},
				},
			},
			score: 0.625,
		},
		{
			name: "AltairSingleAttestationDistance5",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.BeaconBlock{
					Slot:       12349,
					ParentRoot: testutil.HexToRoot("0x0505050505050505050505050505050505050505050505050505050505050505"),
					Body: &altair.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot:            12348,
									BeaconBlockRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0404040404040404040404040404040404040404040404040404040404040404"),
										Epoch: 385,
									},
								},
							},
						},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits: bitfield.NewBitvector512(),
						},
					},
				},
			},
			score: 0.625,
		},
		{
			name: "AltairSingleAttestationDistance6",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.BeaconBlock{
					Slot:       12350,
					ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
					Body: &altair.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot: 12339,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x0707070707070707070707070707070707070707070707070707070707070707"),
										Epoch: 385,
									},
								},
							},
						},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits: bitfield.NewBitvector512(),
						},
					},
				},
			},
			score: 0.40625,
		},
		{
			name: "AltairOverlappingAttestations",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.BeaconBlock{
					Slot:       12345,
					ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
					Body: &altair.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot: 12343,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x4343434343434343434343434343434343434343434343434343434343434343"),
										Epoch: 385,
									},
								},
							},
							{
								AggregationBits: bitList(2, 128),
								Data: &phase0.AttestationData{
									Slot: 12343,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x4343434343434343434343434343434343434343434343434343434343434343"),
										Epoch: 385,
									},
								},
							},
						},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits: bitfield.NewBitvector512(),
						},
					},
				},
			},
			score: 1.25,
		},
		{
			name: "AltairParentMissing",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.BeaconBlock{
					Slot:       12345,
					ParentRoot: testutil.HexToRoot("0x1111111111111111111111111111111111111111111111111111111111111111"),
					Body: &altair.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot:            12344,
									BeaconBlockRoot: testutil.HexToRoot("0x1111111111111111111111111111111111111111111111111111111111111111"),
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x4444444444444444444444444444444444444444444444444444444444444444"),
										Epoch: 385,
									},
								},
							},
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot:            12343,
									BeaconBlockRoot: testutil.HexToRoot("0x1111111111111111111111111111111111111111111111111111111111111111"),
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x4343434343434343434343434343434343434343434343434343434343434343"),
										Epoch: 385,
									},
								},
							},
						},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits: bitfield.NewBitvector512(),
						},
					},
				},
			},
			score: 0.84375 + 0.625,
		},
		{
			name: "PriorVotes",
			priorBlocks: map[phase0.Root]*priorBlockVotes{
				// Chain with middle block orphaned.
				testutil.HexToRoot("0x4141414141414141414141414141414141414141414141414141414141414141"): {
					parent: testutil.HexToRoot("0x4040404040404040404040404040404040404040404040404040404040404040"),
					slot:   12341,
				},
				testutil.HexToRoot("0x4242424242424242424242424242424242424242424242424242424242424242"): {
					parent: testutil.HexToRoot("0x4141414141414141414141414141414141414141414141414141414141414141"),
					slot:   12342,
					votes: map[phase0.Slot]map[phase0.CommitteeIndex]bitfield.Bitlist{
						// This block is orphaned so its votes should be ignored.
						12342: {
							0: bitList(5, 128),
						},
					},
				},
				testutil.HexToRoot("0x4343434343434343434343434343434343434343434343434343434343434343"): {
					parent: testutil.HexToRoot("0x4141414141414141414141414141414141414141414141414141414141414141"),
					slot:   12343,
					votes: map[phase0.Slot]map[phase0.CommitteeIndex]bitfield.Bitlist{
						// This block is a recent ancestore so its votes should be considered.
						12342: {
							0: bitList(2, 128),
						},
					},
				},
			},
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.BeaconBlock{
					Slot:       12344,
					ParentRoot: testutil.HexToRoot("0x4343434343434343434343434343434343434343434343434343434343434343"),
					Body: &altair.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(5, 128),
								Data: &phase0.AttestationData{
									BeaconBlockRoot: testutil.HexToRoot("0x4242424242424242424242424242424242424242424242424242424242424242"),
									Slot:            12342,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x4242424242424242424242424242424242424242424242424242424242424242"),
										Epoch: 385,
									},
								},
							},
						},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits: bitfield.NewBitvector512(),
						},
					},
				},
			},
			score: 1.875,
		},
		{
			name: "TargetCorrect",
			priorBlocks: map[phase0.Root]*priorBlockVotes{
				testutil.HexToRoot("0x4444444444444444444444444444444444444444444444444444444444444444"): {
					root:   testutil.HexToRoot("0x4444444444444444444444444444444444444444444444444444444444444444"),
					parent: testutil.HexToRoot("0x2020202020202020202020202020202020202020202020202020202020202020"),
					slot:   12344,
				},
				testutil.HexToRoot("0x2020202020202020202020202020202020202020202020202020202020202020"): {
					root:   testutil.HexToRoot("0x2020202020202020202020202020202020202020202020202020202020202020"),
					parent: testutil.HexToRoot("0x1919191919191919191919191919191919191919191919191919191919191919"),
					slot:   12320,
				},
			},
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.BeaconBlock{
					Slot:       12345,
					ParentRoot: testutil.HexToRoot("0x4444444444444444444444444444444444444444444444444444444444444444"),
					Body: &altair.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									BeaconBlockRoot: testutil.HexToRoot("0x4444444444444444444444444444444444444444444444444444444444444444"),
									Slot:            12344,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x2020202020202020202020202020202020202020202020202020202020202020"),
										Epoch: 385,
									},
								},
							},
						},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits: bitfield.NewBitvector512(),
						},
					},
				},
			},
			score: 0.84375,
		},
		{
			name: "TargetIncorrect",
			priorBlocks: map[phase0.Root]*priorBlockVotes{
				testutil.HexToRoot("0x4444444444444444444444444444444444444444444444444444444444444444"): {
					root:   testutil.HexToRoot("0x4444444444444444444444444444444444444444444444444444444444444444"),
					parent: testutil.HexToRoot("0x2020202020202020202020202020202020202020202020202020202020202020"),
					slot:   12344,
				},
				testutil.HexToRoot("0x2020202020202020202020202020202020202020202020202020202020202020"): {
					root:   testutil.HexToRoot("0x2020202020202020202020202020202020202020202020202020202020202020"),
					parent: testutil.HexToRoot("0x1919191919191919191919191919191919191919191919191919191919191919"),
					slot:   12320,
				},
			},
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.BeaconBlock{
					Slot:       12345,
					ParentRoot: testutil.HexToRoot("0x4444444444444444444444444444444444444444444444444444444444444444"),
					Body: &altair.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									BeaconBlockRoot: testutil.HexToRoot("0x4444444444444444444444444444444444444444444444444444444444444444"),
									Slot:            12344,
									Target: &phase0.Checkpoint{
										Root:  testutil.HexToRoot("0x1515151515151515151515151515151515151515151515151515151515151515"),
										Epoch: 385,
									},
								},
							},
						},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits: bitfield.NewBitvector512(),
						},
					},
				},
			},
			score: 0.4375,
		},
		{
			name: "InvalidVersion",
			block: &spec.VersionedBeaconBlock{
				Version: spec.DataVersion(999),
				Altair: &altair.BeaconBlock{
					Slot: 12345,
					Body: &altair.BeaconBlockBody{
						Attestations: []*phase0.Attestation{
							{
								AggregationBits: bitList(1, 128),
								Data: &phase0.AttestationData{
									Slot: 12343,
								},
							},
							{
								AggregationBits: bitList(2, 128),
								Data: &phase0.AttestationData{
									Slot: 12343,
								},
							},
						},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits: bitfield.NewBitvector512(),
						},
					},
				},
			},
			score: 0,
		},
	}

	ctx := context.Background()

	genesisTime := time.Now()
	slotDuration := 12 * time.Second
	slotsPerEpoch := uint64(32)
	genesisTimeProvider := mock.NewGenesisTimeProvider(genesisTime)
	slotDurationProvider := mock.NewSlotDurationProvider(slotDuration)
	slotsPerEpochProvider := mock.NewSlotsPerEpochProvider(slotsPerEpoch)
	specProvider := mock.NewSpecProvider()

	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisTimeProvider(genesisTimeProvider),
		standardchaintime.WithSlotDurationProvider(slotDurationProvider),
		standardchaintime.WithSlotsPerEpochProvider(slotsPerEpochProvider),
	)
	require.NoError(t, err)

	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{
		testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"): phase0.Slot(12344),
		testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"): phase0.Slot(12345),
		testutil.HexToRoot("0x0303030303030303030303030303030303030303030303030303030303030303"): phase0.Slot(12346),
		testutil.HexToRoot("0x0404040404040404040404040404040404040404040404040404040404040404"): phase0.Slot(12347),
		testutil.HexToRoot("0x0505050505050505050505050505050505050505050505050505050505050505"): phase0.Slot(12348),
	})
	blockToSlotCache := cacheSvc.(cache.BlockRootToSlotProvider)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := New(ctx,
				WithLogLevel(zerolog.Disabled),
				WithTimeout(2*time.Second),
				WithClientMonitor(null.New(context.Background())),
				WithEventsProvider(mock.NewEventsProvider()),
				WithChainTimeService(chainTime),
				WithSpecProvider(specProvider),
				WithProcessConcurrency(6),
				WithBeaconBlockProposalProviders(map[string]eth2client.BeaconBlockProposalProvider{
					"one": mock.NewBeaconBlockProposalProvider(),
				}),
				WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				WithBlockRootToSlotCache(blockToSlotCache),
			)
			require.NoError(t, err)
			if test.priorBlocks != nil {
				s.priorBlocksVotes = test.priorBlocks
			}
			score := s.scoreBeaconBlockProposal(context.Background(), test.name, test.block)
			assert.Equal(t, test.score, score)
		})
	}
}
