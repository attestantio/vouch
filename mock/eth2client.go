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

package mock

import (
	"context"
	"errors"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
)

// GenesisTimeProvider is a mock for eth2client.GenesisTimeProvider.
type GenesisTimeProvider struct {
	genesisTime time.Time
}

// NewGenesisTimeProvider returns a mock genesis time provider with the provided value.
func NewGenesisTimeProvider(genesisTime time.Time) eth2client.GenesisTimeProvider {
	return &GenesisTimeProvider{
		genesisTime: genesisTime,
	}
}

// GenesisTime is a mock.
func (m *GenesisTimeProvider) GenesisTime(ctx context.Context) (time.Time, error) {
	return m.genesisTime, nil
}

// SlotDurationProvider is a mock for eth2client.SlotDurationProvider.
type SlotDurationProvider struct {
	slotDuration time.Duration
}

// NewSlotDurationProvider returns a mock slot duration provider with the provided value.
func NewSlotDurationProvider(slotDuration time.Duration) eth2client.SlotDurationProvider {
	return &SlotDurationProvider{
		slotDuration: slotDuration,
	}
}

// SlotDuration is a mock.
func (m *SlotDurationProvider) SlotDuration(ctx context.Context) (time.Duration, error) {
	return m.slotDuration, nil
}

// SlotsPerEpochProvider is a mock for eth2client.SlotsPerEpochProvider.
type SlotsPerEpochProvider struct {
	slotsPerEpoch uint64
}

// NewSlotsPerEpochProvider returns a mock slots per epoch provider with the provided value.
func NewSlotsPerEpochProvider(slotsPerEpoch uint64) eth2client.SlotsPerEpochProvider {
	return &SlotsPerEpochProvider{
		slotsPerEpoch: slotsPerEpoch,
	}
}

// SlotsPerEpoch is a mock.
func (m *SlotsPerEpochProvider) SlotsPerEpoch(ctx context.Context) (uint64, error) {
	return m.slotsPerEpoch, nil
}

// AttestationSubmitter is a mock for eth2client.AttestationSubmitter.
type AttestationSubmitter struct{}

// NewAttestationSubmitter returns a mock attestation submitter.
func NewAttestationSubmitter() eth2client.AttestationSubmitter {
	return &AttestationSubmitter{}
}

// SubmitAttestation is a mock.
func (m *AttestationSubmitter) SubmitAttestation(ctx context.Context, attestation *spec.Attestation) error {
	return nil
}

// ErroringAttestationSubmitter is a mock for eth2client.AttestationSubmitter that returns errors.
type ErroringAttestationSubmitter struct{}

// NewErroringAttestationSubmitter returns a mock attestation submitter.
func NewErroringAttestationSubmitter() eth2client.AttestationSubmitter {
	return &ErroringAttestationSubmitter{}
}

// SubmitAttestation is a mock.
func (m *ErroringAttestationSubmitter) SubmitAttestation(ctx context.Context, attestation *spec.Attestation) error {
	return errors.New("error")
}

// BeaconBlockSubmitter is a mock for eth2client.BeaconBlockSubmitter.
type BeaconBlockSubmitter struct{}

// NewBeaconBlockSubmitter returns a mock beacon block submitter.
func NewBeaconBlockSubmitter() eth2client.BeaconBlockSubmitter {
	return &BeaconBlockSubmitter{}
}

// SubmitBeaconBlock is a mock.
func (m *BeaconBlockSubmitter) SubmitBeaconBlock(ctx context.Context, bloc *spec.SignedBeaconBlock) error {
	return nil
}

// ErroringBeaconBlockSubmitter is a mock for eth2client.BeaconBlockSubmitter that returns errors.
type ErroringBeaconBlockSubmitter struct{}

// NewErroringBeaconBlockSubmitter returns a mock beacon block submitter.
func NewErroringBeaconBlockSubmitter() eth2client.BeaconBlockSubmitter {
	return &ErroringBeaconBlockSubmitter{}
}

// SubmitBeaconBlock is a mock.
func (m *ErroringBeaconBlockSubmitter) SubmitBeaconBlock(ctx context.Context, bloc *spec.SignedBeaconBlock) error {
	return errors.New("error")
}

// AggregateAttestationsSubmitter is a mock for eth2client.AggregateAttestationsSubmitter.
type AggregateAttestationsSubmitter struct{}

// NewAggregateAttestationsSubmitter returns a mock aggregate attestation submitter.
func NewAggregateAttestationsSubmitter() eth2client.AggregateAttestationsSubmitter {
	return &AggregateAttestationsSubmitter{}
}

// SubmitAggregateAttestations is a mock.
func (m *AggregateAttestationsSubmitter) SubmitAggregateAttestations(ctx context.Context, aggregateAndProofs []*spec.SignedAggregateAndProof) error {
	return nil
}

// ErroringAggregateAttestationsSubmitter is a mock for eth2client.AggregateAttestationsSubmitter that returns errors.
type ErroringAggregateAttestationsSubmitter struct{}

// NewErroringAggregateAttestationsSubmitter returns a mock aggregate attestation submitter.
func NewErroringAggregateAttestationsSubmitter() eth2client.AggregateAttestationsSubmitter {
	return &ErroringAggregateAttestationsSubmitter{}
}

// SubmitAggregateAttestations is a mock.
func (m *ErroringAggregateAttestationsSubmitter) SubmitAggregateAttestations(ctx context.Context, aggregateAndProofs []*spec.SignedAggregateAndProof) error {
	return errors.New("error")
}

// BeaconCommitteeSubscriptionsSubmitter is a mock for eth2client.BeaconCommitteeSubscriptionsSubmitter.
type BeaconCommitteeSubscriptionsSubmitter struct{}

// NewBeaconCommitteeSubscriptionsSubmitter returns a mock beacon committee subscriptions submitter.
func NewBeaconCommitteeSubscriptionsSubmitter() eth2client.BeaconCommitteeSubscriptionsSubmitter {
	return &BeaconCommitteeSubscriptionsSubmitter{}
}

// SubmitBeaconCommitteeSubscriptions is a mock.
func (m *BeaconCommitteeSubscriptionsSubmitter) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*eth2client.BeaconCommitteeSubscription) error {
	return nil
}

// ErroringBeaconCommitteeSubscriptionsSubmitter is a mock for eth2client.BeaconCommitteeSubscriptionsSubmitter that returns errors.
type ErroringBeaconCommitteeSubscriptionsSubmitter struct{}

// NewErroringBeaconCommitteeSubscriptionsSubmitter returns a mock beacon committee subscriptions submitter.
func NewErroringBeaconCommitteeSubscriptionsSubmitter() eth2client.BeaconCommitteeSubscriptionsSubmitter {
	return &ErroringBeaconCommitteeSubscriptionsSubmitter{}
}

// SubmitBeaconCommitteeSubscriptions is a mock.
func (m *ErroringBeaconCommitteeSubscriptionsSubmitter) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*eth2client.BeaconCommitteeSubscription) error {
	return errors.New("error")
}

// BeaconBlockProposalProvider is a mock for eth2client.BeaconBlockProposalProvider.
type BeaconBlockProposalProvider struct{}

// NewBeaconBlockProposalProvider returns a mock beacon block proposal provider.
func NewBeaconBlockProposalProvider() eth2client.BeaconBlockProposalProvider {
	return &BeaconBlockProposalProvider{}
}

// BeaconBlockProposal is a mock.
func (m *BeaconBlockProposalProvider) BeaconBlockProposal(ctx context.Context, slot uint64, randaoReveal []byte, graffiti []byte) (*spec.BeaconBlock, error) {
	// Graffiti should be 32 bytes.
	fixedGraffiti := make([]byte, 32)
	copy(fixedGraffiti, graffiti)

	// Build a beacon block.

	// Create a few attestations.
	attestations := make([]*spec.Attestation, 4)
	for i := uint64(0); i < 4; i++ {
		aggregationBits := bitfield.NewBitlist(128)
		aggregationBits.SetBitAt(i, true)
		attestations[i] = &spec.Attestation{
			AggregationBits: aggregationBits,
			Data: &spec.AttestationData{
				Slot:  slot - 1,
				Index: i,
				BeaconBlockRoot: []byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
				Source: &spec.Checkpoint{
					Epoch: 0,
					Root: []byte{
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					},
				},
				Target: &spec.Checkpoint{
					Epoch: 1,
					Root: []byte{
						0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
						0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
					},
				},
			},
			Signature: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
				0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
				0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
			},
		}
	}

	block := &spec.BeaconBlock{
		Slot:          slot,
		ProposerIndex: 1,
		ParentRoot: []byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		StateRoot: []byte{
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
		},
		Body: &spec.BeaconBlockBody{
			RANDAOReveal: randaoReveal,
			ETH1Data: &spec.ETH1Data{
				DepositRoot: []byte{
					0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
					0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
				},
				DepositCount: 16384,
				BlockHash: []byte{
					0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
					0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
				},
			},
			Graffiti:          fixedGraffiti,
			ProposerSlashings: []*spec.ProposerSlashing{},
			AttesterSlashings: []*spec.AttesterSlashing{},
			Attestations:      attestations,
			Deposits:          []*spec.Deposit{},
			VoluntaryExits:    []*spec.SignedVoluntaryExit{},
		},
	}

	return block, nil
}
