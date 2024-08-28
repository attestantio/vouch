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
	"github.com/attestantio/vouch/testing/logger"
	"github.com/attestantio/vouch/testutil"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func bitList(set uint64, total uint64) bitfield.Bitlist {
	bits := bitfield.NewBitlist(total)
	for i := uint64(0); i < set; i++ {
		bits.SetBitAt(i, true)
	}
	return bits
}

// TestUpdateBlockVotes tests the internal function updateBlockVotes.
func TestUpdateBlockVotes(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		block      *spec.VersionedSignedBeaconBlock
		logEntries []string
	}{
		{
			name:  "Nil",
			block: nil,
		},
		{
			name:  "Empty",
			block: &spec.VersionedSignedBeaconBlock{},
			logEntries: []string{
				"Failed to obtain proposed block's slot",
			},
		},
		{
			name: "MissingAttestations",
			block: &spec.VersionedSignedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.SignedBeaconBlock{
					Message: &altair.BeaconBlock{
						Slot: 12345,
					},
				},
			},
			logEntries: []string{
				"Failed to obtain proposed block's attestations",
			},
		},
		{
			name: "EmptyAttestations",
			block: &spec.VersionedSignedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.SignedBeaconBlock{
					Message: &altair.BeaconBlock{
						Slot: 12345,
						Body: &altair.BeaconBlockBody{
							ETH1Data:     &phase0.ETH1Data{},
							Attestations: []*phase0.Attestation{},
						},
					},
				},
			},
			logEntries: []string{
				"Failed to obtain proposed block's root",
			},
		},
		{
			name: "SingleAttestation",
			block: &spec.VersionedSignedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.SignedBeaconBlock{
					Message: &altair.BeaconBlock{
						Slot:       12345,
						ParentRoot: testutil.HexToRoot("0x0101010101010101010101010101010101010101010101010101010101010101"),
						StateRoot:  testutil.HexToRoot("0x0202020202020202020202020202020202020202020202020202020202020202"),
						Body: &altair.BeaconBlockBody{
							RANDAOReveal: testutil.HexToSignature("0x030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303"),
							ETH1Data: &phase0.ETH1Data{
								DepositRoot: testutil.HexToRoot("0x1010101010101010101010101010101010101010101010101010101010101010"),
								BlockHash:   testutil.HexToBytes("0x1111111111111111111111111111111111111111111111111111111111111111"),
							},
							Graffiti: testutil.HexToBytes32("0x0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad"),
							Attestations: []*phase0.Attestation{
								{
									AggregationBits: bitList(10, 128),
									Data: &phase0.AttestationData{
										Slot:            12344,
										Index:           0,
										BeaconBlockRoot: testutil.HexToRoot("0x0404040404040404040404040404040404040404040404040404040404040404"),
										Source: &phase0.Checkpoint{
											Root:  testutil.HexToRoot("0x0505050505050505050505050505050505050505050505050505050505050505"),
											Epoch: 384,
										},
										Target: &phase0.Checkpoint{
											Root:  testutil.HexToRoot("0x0606060606060606060606060606060606060606060606060606060606060606"),
											Epoch: 385,
										},
									},
								},
							},
							SyncAggregate: &altair.SyncAggregate{
								SyncCommitteeBits:      bitfield.NewBitvector512(),
								SyncCommitteeSignature: testutil.HexToSignature("0x080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808"),
							},
						},
					},
					Signature: testutil.HexToSignature("0x070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707"),
				},
			},
			logEntries: []string{
				"Set votes for slot",
			},
		},
	}

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	blockToSlotCache := cacheSvc.(cache.BlockRootToSlotProvider)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			s, err := New(ctx,
				WithLogLevel(zerolog.TraceLevel),
				WithTimeout(2*time.Second),
				WithEventsProvider(mock.NewEventsProvider()),
				WithChainTimeService(chainTime),
				WithSpecProvider(specProvider),
				WithProcessConcurrency(6),
				WithProposalProviders(map[string]eth2client.ProposalProvider{
					"one": mock.NewProposalProvider(),
				}),
				WithSignedBeaconBlockProvider(mock.NewSignedBeaconBlockProvider()),
				WithBlockRootToSlotCache(blockToSlotCache),
			)
			require.NoError(t, err)

			s.updateBlockVotes(ctx, test.block)
			for _, entry := range test.logEntries {
				capture.AssertHasEntry(t, entry)
			}
		})
	}
}
