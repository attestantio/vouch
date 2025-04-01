// Copyright © 2025 Attestant Limited.
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

package majority

import (
	"context"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

func TestBuildAttestationData(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		responses map[phase0.Root][]*attestationDataResponse
		res       *phase0.AttestationData
		err       string
	}{
		{
			name: "HeadDisagreement",
			responses: map[phase0.Root][]*attestationDataResponse{
				{0x01}: {
					{
						provider: "1",
						attestationData: &phase0.AttestationData{
							Slot:            170,
							BeaconBlockRoot: phase0.Root{0x99},
							Source: &phase0.Checkpoint{
								Epoch: 5,
								Root:  phase0.Root{0xbb},
							},
							Target: &phase0.Checkpoint{
								Epoch: 6,
								Root:  phase0.Root{0xdd},
							},
						},
					},
				},
				{0x02}: {
					{
						provider: "2",
						attestationData: &phase0.AttestationData{
							Slot:            170,
							BeaconBlockRoot: phase0.Root{0xaa},
							Source: &phase0.Checkpoint{
								Epoch: 5,
								Root:  phase0.Root{0xbb},
							},
							Target: &phase0.Checkpoint{
								Epoch: 6,
								Root:  phase0.Root{0xdd},
							},
						},
					},
				},
			},
			res: &phase0.AttestationData{
				Slot: 170,
				Source: &phase0.Checkpoint{
					Epoch: 5,
					Root:  phase0.Root{0xbb},
				},
				Target: &phase0.Checkpoint{
					Epoch: 6,
					Root:  phase0.Root{0xdd},
				},
			},
		},
		{
			name: "SourceDisagreement",
			responses: map[phase0.Root][]*attestationDataResponse{
				{0x01}: {
					{
						provider: "1",
						attestationData: &phase0.AttestationData{
							Slot:            170,
							BeaconBlockRoot: phase0.Root{0x99},
							Source: &phase0.Checkpoint{
								Epoch: 5,
								Root:  phase0.Root{0xbb},
							},
							Target: &phase0.Checkpoint{
								Epoch: 6,
								Root:  phase0.Root{0xdd},
							},
						},
					},
				},
				{0x02}: {
					{
						provider: "2",
						attestationData: &phase0.AttestationData{
							Slot:            170,
							BeaconBlockRoot: phase0.Root{0x99},
							Source: &phase0.Checkpoint{
								Epoch: 5,
								Root:  phase0.Root{0xcc},
							},
							Target: &phase0.Checkpoint{
								Epoch: 6,
								Root:  phase0.Root{0xdd},
							},
						},
					},
				},
			},
			err: "could not build majority attestation data; no source checkpoint",
		},
		{
			name: "TargetDisagreement",
			responses: map[phase0.Root][]*attestationDataResponse{
				{0x01}: {
					{
						provider: "1",
						attestationData: &phase0.AttestationData{
							Slot:            170,
							BeaconBlockRoot: phase0.Root{0x99},
							Source: &phase0.Checkpoint{
								Epoch: 5,
								Root:  phase0.Root{0xbb},
							},
							Target: &phase0.Checkpoint{
								Epoch: 6,
								Root:  phase0.Root{0xdd},
							},
						},
					},
				},
				{0x02}: {
					{
						provider: "2",
						attestationData: &phase0.AttestationData{
							Slot:            170,
							BeaconBlockRoot: phase0.Root{0x99},
							Source: &phase0.Checkpoint{
								Epoch: 5,
								Root:  phase0.Root{0xbb},
							},
							Target: &phase0.Checkpoint{
								Epoch: 6,
								Root:  phase0.Root{0xee},
							},
						},
					},
				},
			},
			err: "could not build majority attestation data; no target checkpoint",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := &Service{
				threshold: 2,
			}
			res, err := s.recombineAttestationData(ctx, time.Now(), test.responses)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
			}
		})
	}
}
