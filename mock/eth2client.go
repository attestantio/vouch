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
	"encoding/hex"
	"errors"
	"strings"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
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

// ErroringSlotsPerEpochProvider is a mock for eth2client.SlotsPerEpochProvider.
type ErroringSlotsPerEpochProvider struct{}

// NewErroringSlotsPerEpochProvider returns a mock slots per epoch provider that errors.
func NewErroringSlotsPerEpochProvider() eth2client.SlotsPerEpochProvider {
	return &ErroringSlotsPerEpochProvider{}
}

// SlotsPerEpoch is a mock.
func (m *ErroringSlotsPerEpochProvider) SlotsPerEpoch(ctx context.Context) (uint64, error) {
	return 0, errors.New("error")
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
func (m *BeaconCommitteeSubscriptionsSubmitter) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*api.BeaconCommitteeSubscription) error {
	return nil
}

// ErroringBeaconCommitteeSubscriptionsSubmitter is a mock for eth2client.BeaconCommitteeSubscriptionsSubmitter that returns errors.
type ErroringBeaconCommitteeSubscriptionsSubmitter struct{}

// NewErroringBeaconCommitteeSubscriptionsSubmitter returns a mock beacon committee subscriptions submitter.
func NewErroringBeaconCommitteeSubscriptionsSubmitter() eth2client.BeaconCommitteeSubscriptionsSubmitter {
	return &ErroringBeaconCommitteeSubscriptionsSubmitter{}
}

// SubmitBeaconCommitteeSubscriptions is a mock.
func (m *ErroringBeaconCommitteeSubscriptionsSubmitter) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*api.BeaconCommitteeSubscription) error {
	return errors.New("error")
}

// BeaconBlockProposalProvider is a mock for eth2client.BeaconBlockProposalProvider.
type BeaconBlockProposalProvider struct{}

// NewBeaconBlockProposalProvider returns a mock beacon block proposal provider.
func NewBeaconBlockProposalProvider() eth2client.BeaconBlockProposalProvider {
	return &BeaconBlockProposalProvider{}
}

// BeaconBlockProposal is a mock.
func (m *BeaconBlockProposalProvider) BeaconBlockProposal(ctx context.Context, slot spec.Slot, randaoReveal spec.BLSSignature, graffiti []byte) (*spec.BeaconBlock, error) {
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
				Index: spec.CommitteeIndex(i),
				BeaconBlockRoot: spec.Root([32]byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				}),
				Source: &spec.Checkpoint{
					Epoch: 0,
					Root: spec.Root([32]byte{
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					}),
				},
				Target: &spec.Checkpoint{
					Epoch: 1,
					Root: spec.Root([32]byte{
						0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
						0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
					}),
				},
			},
			Signature: spec.BLSSignature([96]byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
				0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
				0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
			}),
		}
	}

	block := &spec.BeaconBlock{
		Slot:          slot,
		ProposerIndex: 1,
		ParentRoot: spec.Root([32]byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		}),
		StateRoot: spec.Root([32]byte{
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
		}),
		Body: &spec.BeaconBlockBody{
			RANDAOReveal: randaoReveal,
			ETH1Data: &spec.ETH1Data{
				DepositRoot: spec.Root([32]byte{
					0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
					0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
				}),
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

// SignedBeaconBlockProvider is a mock for eth2client.SignedBeaconBlockProvider.
type SignedBeaconBlockProvider struct{}

// NewSignedBeaconBlockProvider returns a mock beacon block proposal provider.
func NewSignedBeaconBlockProvider() eth2client.SignedBeaconBlockProvider {
	return &SignedBeaconBlockProvider{}
}

// SignedBeaconBlock is a mock.
func (m *SignedBeaconBlockProvider) SignedBeaconBlock(ctx context.Context, stateID string) (*spec.SignedBeaconBlock, error) {
	return &spec.SignedBeaconBlock{
		Message: &spec.BeaconBlock{
			Slot: 123,
		},
	}, nil
}

// BeaconProposerDomainProvider is a mock for eth2client.BeaconProposerDomainProvider.
type BeaconProposerDomainProvider struct{}

// NewBeaconProposerDomainProvider returns a mock beacon proposer domain provider.
func NewBeaconProposerDomainProvider() eth2client.BeaconProposerDomainProvider {
	return &BeaconProposerDomainProvider{}
}

// BeaconProposerDomain is a mock.
func (m *BeaconProposerDomainProvider) BeaconProposerDomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{0x00, 0x00, 0x00, 0x00}, nil
}

// ErroringBeaconProposerDomainProvider is a mock for eth2client.BeaconProposerDomainProvider.
type ErroringBeaconProposerDomainProvider struct{}

// NewErroringBeaconProposerDomainProvider returns a mock beacon proposer domain provider that errors.
func NewErroringBeaconProposerDomainProvider() eth2client.BeaconProposerDomainProvider {
	return &ErroringBeaconProposerDomainProvider{}
}

// BeaconProposerDomain is a mock.
func (m *ErroringBeaconProposerDomainProvider) BeaconProposerDomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{}, errors.New("error")
}

// BeaconAttesterDomainProvider is a mock for eth2client.BeaconAttesterDomainProvider.
type BeaconAttesterDomainProvider struct{}

// NewBeaconAttesterDomainProvider returns a mock beacon attester domain provider.
func NewBeaconAttesterDomainProvider() eth2client.BeaconAttesterDomainProvider {
	return &BeaconAttesterDomainProvider{}
}

// BeaconAttesterDomain is a mock.
func (m *BeaconAttesterDomainProvider) BeaconAttesterDomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{0x01, 0x00, 0x00, 0x00}, nil
}

// ErroringBeaconAttesterDomainProvider is a mock for eth2client.BeaconAttesterDomainProvider.
type ErroringBeaconAttesterDomainProvider struct{}

// NewErroringBeaconAttesterDomainProvider returns a mock beacon attester domain provider that errors.
func NewErroringBeaconAttesterDomainProvider() eth2client.BeaconAttesterDomainProvider {
	return &ErroringBeaconAttesterDomainProvider{}
}

// BeaconAttesterDomain is a mock.
func (m *ErroringBeaconAttesterDomainProvider) BeaconAttesterDomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{}, errors.New("error")
}

// RANDAODomainProvider is a mock for eth2client.RANDAODomainProvider.
type RANDAODomainProvider struct{}

// NewRANDAODomainProvider returns a mock RANDAO domain provider.
func NewRANDAODomainProvider() eth2client.RANDAODomainProvider {
	return &RANDAODomainProvider{}
}

// RANDAODomain is a mock.
func (m *RANDAODomainProvider) RANDAODomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{0x02, 0x00, 0x00, 0x00}, nil
}

// ErroringRANDAODomainProvider is a mock for eth2client.RANDAODomainProvider.
type ErroringRANDAODomainProvider struct{}

// NewErroringRANDAODomainProvider returns a mock RANDAO domain provider that errors.
func NewErroringRANDAODomainProvider() eth2client.RANDAODomainProvider {
	return &ErroringRANDAODomainProvider{}
}

// RANDAODomain is a mock.
func (m *ErroringRANDAODomainProvider) RANDAODomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{}, errors.New("error")
}

// DepositDomainProvider is a mock for eth2client.DepositDomainProvider.
type DepositDomainProvider struct{}

// NewDepositDomainProvider returns a mock deposit domain provider.
func NewDepositDomainProvider() eth2client.DepositDomainProvider {
	return &DepositDomainProvider{}
}

// DepositDomain is a mock.
func (m *DepositDomainProvider) DepositDomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{0x03, 0x00, 0x00, 0x00}, nil
}

// ErroringDepositDomainProvider is a mock for eth2client.DepositDomainProvider.
type ErroringDepositDomainProvider struct{}

// NewErroringDepositDomainProvider returns a mock deposit domain provider that errors.
func NewErroringDepositDomainProvider() eth2client.DepositDomainProvider {
	return &DepositDomainProvider{}
}

// DepositDomain is a mock.
func (m *ErroringDepositDomainProvider) DepositDomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{}, errors.New("error")
}

// VoluntaryExitDomainProvider is a mock for eth2client.VoluntaryExitDomainProvider.
type VoluntaryExitDomainProvider struct{}

// NewVoluntaryExitDomainProvider returns a mock voluntary exit domain provider.
func NewVoluntaryExitDomainProvider() eth2client.VoluntaryExitDomainProvider {
	return &VoluntaryExitDomainProvider{}
}

// VoluntaryExitDomain is a mock.
func (m *VoluntaryExitDomainProvider) VoluntaryExitDomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{0x04, 0x00, 0x00, 0x00}, nil
}

// ErroringVoluntaryExitDomainProvider is a mock for eth2client.VoluntaryExitDomainProvider.
type ErroringVoluntaryExitDomainProvider struct{}

// NewErroringVoluntaryExitDomainProvider returns a mock voluntary exit domain provider that errors.
func NewErroringVoluntaryExitDomainProvider() eth2client.VoluntaryExitDomainProvider {
	return &VoluntaryExitDomainProvider{}
}

// VoluntaryExitDomain is a mock.
func (m *ErroringVoluntaryExitDomainProvider) VoluntaryExitDomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{}, errors.New("error")
}

// SelectionProofDomainProvider is a mock for eth2client.SelectionProofDomainProvider.
type SelectionProofDomainProvider struct{}

// NewSelectionProofDomainProvider returns a mock selection proof domain provider.
func NewSelectionProofDomainProvider() eth2client.SelectionProofDomainProvider {
	return &SelectionProofDomainProvider{}
}

// SelectionProofDomain is a mock.
func (m *SelectionProofDomainProvider) SelectionProofDomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{0x05, 0x00, 0x00, 0x00}, nil
}

// ErroringSelectionProofDomainProvider is a mock for eth2client.SelectionProofDomainProvider.
type ErroringSelectionProofDomainProvider struct{}

// NewErroringSelectionProofDomainProvider returns a mock selection proof domain provider that errors.
func NewErroringSelectionProofDomainProvider() eth2client.SelectionProofDomainProvider {
	return &ErroringSelectionProofDomainProvider{}
}

// SelectionProofDomain is a mock.
func (m *ErroringSelectionProofDomainProvider) SelectionProofDomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{}, errors.New("error")
}

// AggregateAndProofDomainProvider is a mock for eth2client.AggregateAndProofDomainProvider.
type AggregateAndProofDomainProvider struct{}

// NewAggregateAndProofDomainProvider returns a mock aggregate and proof domain provider.
func NewAggregateAndProofDomainProvider() eth2client.AggregateAndProofDomainProvider {
	return &AggregateAndProofDomainProvider{}
}

// AggregateAndProofDomain is a mock.
func (m *AggregateAndProofDomainProvider) AggregateAndProofDomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{0x06, 0x00, 0x00, 0x00}, nil
}

// ErroringAggregateAndProofDomainProvider is a mock for eth2client.AggregateAndProofDomainProvider.
type ErroringAggregateAndProofDomainProvider struct{}

// NewErroringAggregateAndProofDomainProvider returns a mock aggregate and proof domain provider that errors.
func NewErroringAggregateAndProofDomainProvider() eth2client.AggregateAndProofDomainProvider {
	return &ErroringAggregateAndProofDomainProvider{}
}

// AggregateAndProofDomain is a mock.
func (m *ErroringAggregateAndProofDomainProvider) AggregateAndProofDomain(ctx context.Context) (spec.DomainType, error) {
	return spec.DomainType{}, errors.New("error")
}

// DomainProvider is a mock for eth2client.DomainProvider.
type DomainProvider struct{}

// NewDomainProvider returns a mock domain provider.
func NewDomainProvider() eth2client.DomainProvider {
	return &DomainProvider{}
}

// Domain is a mock.
func (m *DomainProvider) Domain(ctx context.Context, domainType spec.DomainType, epoch spec.Epoch) (spec.Domain, error) {
	var domain spec.Domain
	// Put the domain type in the first four bytes, to differentiate signatures.
	copy(domain[:], domainType[:])

	return domain, nil
}

// ErroringDomainProvider is a mock for eth2client.DomainProvider.
type ErroringDomainProvider struct{}

// NewErroringDomainProvider returns a mock signature domain provider that errors.
func NewErroringDomainProvider() eth2client.DomainProvider {
	return &ErroringDomainProvider{}
}

// Domain is a mock.
func (m *ErroringDomainProvider) Domain(ctx context.Context, domainType spec.DomainType, epoch spec.Epoch) (spec.Domain, error) {
	return spec.Domain{}, errors.New("error")
}

// ValidatorsProvider is a mock for eth2client.ValidatorsProvider.
type ValidatorsProvider struct{}

// NewValidatorsProvider returns a mock validators provider.
func NewValidatorsProvider() eth2client.ValidatorsProvider {
	return &ValidatorsProvider{}
}

func _byte(input string) []byte {
	res, _ := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	return res
}

func _blsPubKey(input string) spec.BLSPubKey {
	tmp, _ := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	var res spec.BLSPubKey
	copy(res[:], tmp)
	return res
}

func _epochValidator(index spec.ValidatorIndex, pubKey string, withdrwalCredentials string) *api.Validator {
	return &api.Validator{
		Index:   index,
		Balance: 32000000000,
		Status:  api.ValidatorStateActiveOngoing,
		Validator: &spec.Validator{
			PublicKey:                  _blsPubKey(pubKey),
			WithdrawalCredentials:      _byte(withdrwalCredentials),
			EffectiveBalance:           32000000,
			Slashed:                    false,
			ActivationEligibilityEpoch: 0,
			ActivationEpoch:            0,
			ExitEpoch:                  0xffffffffffffffff,
			WithdrawableEpoch:          0xffffffffffffffff,
		},
	}
}

// Validators is a mock.
func (m *ValidatorsProvider) Validators(ctx context.Context, stateID string, validators []spec.ValidatorIndex) (map[spec.ValidatorIndex]*api.Validator, error) {
	return map[spec.ValidatorIndex]*api.Validator{
		0: _epochValidator(0,
			"0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
			"0x00fad2a6bfb0e7f1f0f45460944fbd8dfa7f37da06a4d13b3983cc90bb46963b"),
		1: _epochValidator(1,
			"0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b",
			"0x00ec7ef7780c9d151597924036262dd28dc60e1228f4da6fecf9d402cb3f3594"),
		2: _epochValidator(2,
			"0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b",
			"0x0036085c6c608e6d048505b04402568c36cce1e025722de44f9c3685a5c80fa6"),
		3: _epochValidator(3,
			"0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e",
			"0x005a7de495bcec04d3b5e74ae09ffe493a9dd06d7dcbf18c78455571e87d901a"),
		4: _epochValidator(4,
			"0x81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e",
			"0x004a28c193c65c91b7ebb5b5d14ffa7f75dc48ad4bc66de82f70fc55a2df1215"),
		5: _epochValidator(5,
			"0xab0bdda0f85f842f431beaccf1250bf1fd7ba51b4100fd64364b6401fda85bb0069b3e715b58819684e7fc0b10a72a34",
			"0x005856ab195b61df2ff5d6ab2fa36f30dab45e42cfa1aaef3ffd899f29bd8641"),
		6: _epochValidator(6,
			"0x9977f1c8b731a8d5558146bfb86caea26434f3c5878b589bf280a42c9159e700e9df0e4086296c20b011d2e78c27d373",
			"0x001c5d9bedbad1b7aff3b80e887e65b3357a695b70b6ee0625c2b2f6f86449f8"),
		7: _epochValidator(7,
			"0xa8d4c7c27795a725961317ef5953a7032ed6d83739db8b0e8a72353d1b8b4439427f7efa2c89caa03cc9f28f8cbab8ac",
			"0x001414bfc6dacca55f974ec910893c8617f9c99da897534c637b50e9fc695323"),
		8: _epochValidator(8,
			"0xa6d310dbbfab9a22450f59993f87a4ce5db6223f3b5f1f30d2c4ec718922d400e0b3c7741de8e59960f72411a0ee10a7",
			"0x00ed09b6181e6f97365e221e70aeebcb2604011d8c4326f3b98ce8d79b031ae8"),
		9: _epochValidator(9,
			"0x9893413c00283a3f9ed9fd9845dda1cea38228d22567f9541dccc357e54a2d6a6e204103c92564cbc05f4905ac7c493a",
			"0x001fe05baa70dd29ce85f694898bb6de3bcde158a825db56906b54141b2a728d"),
		10: _epochValidator(10,
			"0x876dd4705157eb66dc71bc2e07fb151ea53e1a62a0bb980a7ce72d15f58944a8a3752d754f52f4a60dbfc7b18169f268",
			"0x00aa2cfedd0160868d0901664e9d2eac1275dd658e109fabe11c7ad87a07fc0c"),
		11: _epochValidator(11,
			"0xaec922bd7a9b7b1dc21993133b586b0c3041c1e2e04b513e862227b9d7aecaf9444222f7e78282a449622ffc6278915d",
			"0x0076f08e6f40cf14992b7e4f524ea0cf7e1c6fd7dd5200b564c96fc099d601aa"),
		12: _epochValidator(12,
			"0x9314c6de0386635e2799af798884c2ea09c63b9f079e572acc00b06a7faccce501ea4dfc0b1a23b8603680a5e3481327",
			"0x004a581b2ef2b79652a19d3332f6574b0213ddbd179480edbf7ff490823fd5c7"),
		13: _epochValidator(13,
			"0x903e2989e7442ee0a8958d020507a8bd985d3974f5e8273093be00db3935f0500e141b252bd09e3728892c7a8443863c",
			"0x0040c37a4dafa560a7665394aa7502e113ecfbdb72c1ef92826db24601889b87"),
		14: _epochValidator(14,
			"0x84398f539a64cbe01cfcd8c485ea51cd6657b94df93ee9b5dc61e1f18f69da6ca9d4dba63c956a81c68d5d4d4277a60f",
			"0x0047381e2716b14a79e1f102669c615eb3542e9230ed7712b21f305ecc1a43d5"),
		15: _epochValidator(15,
			"0x872c61b4a7f8510ec809e5b023f5fdda2105d024c470ddbbeca4bc74e8280af0d178d749853e8f6a841083ac1b4db98f",
			"0x0020dd5f2223831fce8d1c8fd4148943c9917e1d3a92191651892dc56448451c"),
		16: _epochValidator(16,
			"0x8f467e5723deac7659e1ca273e28410cbaa6d495ab66ae77014f4cd21c64b6b5ab9987c9b5537fe0279bd063fe609be7",
			"0x00b24fc624e56a5ed42a9639691e27e34b783c7237030367bd17cbef65fa6ccf"),
		17: _epochValidator(17,
			"0x8dde8306920812b32def3b663f7c540b49180345d3bcb8d3770790b7dc80030ebc06497feebd1bcf017d918f00bfa88f",
			"0x0018e4071970526ed149970747c6b858307be8b60aa7440ad93c1f351af62923"),
		18: _epochValidator(18,
			"0xab8d3a9bcc160e518fac0756d3e192c74789588ed4a2b1debf0c78f78479ca8edb05b12ce21103076df6af4eb8756ff9",
			"0x00bb019106332edfed624b40e410561513e9fb9e285cbc56a450d499a2b13769"),
		19: _epochValidator(19,
			"0x8d5d3672a233db513df7ad1e8beafeae99a9f0199ed4d949bbedbb6f394030c0416bd99b910e14f73c65b6a11fe6b62e",
			"0x004218c29533321c9aae659d8b2148b87693d6b1eee8e119805e5298f8bf0a33"),
		20: _epochValidator(20,
			"0xa1c76af1545d7901214bb6be06be5d9e458f8e989c19373a920f0018327c83982f6a2ac138260b8def732cb366411ddc",
			"0x0004e3d99964ee8b0b6ed11833ba55fbf7bf80fe8f4e45c4d00a3d4ff6d73c0c"),
		21: _epochValidator(21,
			"0x8dd74e1bb5228fc1fca274fda02b971c1003a4f409bbdfbcfec6426bf2f52addcbbebccdbf45eee6ae11eb5b5ee7244d",
			"0x00037233059d7c629c79ddb7d94b0ef1275ebe55ed20fb80a414548be9ec890a"),
		22: _epochValidator(22,
			"0x954eb88ed1207f891dc3c28fa6cfdf8f53bf0ed3d838f3476c0900a61314d22d4f0a300da3cd010444dd5183e35a593c",
			"0x0056a7b95fd200d2997155b525eacda73baae3f3196a48fb9a513ddd1e7247c3"),
		23: _epochValidator(23,
			"0xaf344fce60dbd5fb850070e6e76a065e1a32485245ef4f413135a86ae703da88407c5d01c71f6bb06a151ff96cca7191",
			"0x005bdba6a856b0df016f8cbad0f9c02a517e2ff2f5db19187e6d1ba155d4b2e5"),
		24: _epochValidator(24,
			"0xae241af60691fda1cf8ca44d49573c55818c53b6141800cca2d488b9a3fba71c0f869179fff50c084657831fbeb42bf4",
			"0x000cc62d0bf911cfba5320da6e1d7407ff744427f74e855fc2444357788d6830"),
		25: _epochValidator(25,
			"0x96746aaba64dc87835ba709332f4d5d7837ada092b439c49d251aecf92aab5dc132e917bf6f59799bc093f976a7bc021",
			"0x006badd5d911c8565362da6e00dde8d2dda73fb9127d5ba26849ae0a0636172b"),
		26: _epochValidator(26,
			"0xb9d1d914df3d4565465c3fd52b5b96e637f9980570cabf5b5d4aadf5a329ac36ad672819d997e735f5052e28b1f0c104",
			"0x00f53dc973d5288e8070cf79ac0168443f3a2703e83f600e6197067aa02ca662"),
		27: _epochValidator(27,
			"0x963528adb5322c2e2c54dc296ffddd2861bb103cbf64646781dfa8a3c2d8a8eda7079d2b3e95600028c44365afbf8879",
			"0x00fa4e26953e907b1ed8032bdd02c9869dbbf521f3cb7bac1c8112ccf45c1d3a"),
		28: _epochValidator(28,
			"0xb245d63d3f9d8ea1807a629fcb1b328cb4d542f35a3d5bc478be0df389dddd712fc4c816ba3fede9a96320ae6b24a7d8",
			"0x00a68cdbfc1e865255d8e436d7bc7fc63c87b5c9c247c9e5de34d4fc26a1adc9"),
		29: _epochValidator(29,
			"0xa98ed496c2f464226500a6ce04602ff9ef133ed6316f372f6c744aee165149f7e578b12780e0eacec307ae6907351d99",
			"0x002f6d1f79f89a308365af4dbb8a850918db7844165b36e43c64e1a35b4af0b2"),
		30: _epochValidator(30,
			"0xae00fc3de831b09661a0ac02873c45c84cb2b58cffb6430a3f607e4c3fa1e0932397f11307cd169cdc6f79c463527260",
			"0x00e6ef2894304bc790c9e6b3a75815f10ceea391d8ebb9a27e07bf54360e9b3d"),
		31: _epochValidator(31,
			"0xa4855c83d868f772a579133d9f23818008417b743e8447e235d8eb78b1d8f8a9f63f98c551beb7de254400f89592314d",
			"0x0077c6a139204cbdaae840e0beb43b384c35182aabbc1104207b6a5a626fe75b"),
	}, nil
}

// ValidatorsByPubKey is a mock.
func (m *ValidatorsProvider) ValidatorsByPubKey(ctx context.Context, stateID string, validators []spec.BLSPubKey) (map[spec.ValidatorIndex]*api.Validator, error) {
	return map[spec.ValidatorIndex]*api.Validator{
		0: _epochValidator(0,
			"0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
			"0x00fad2a6bfb0e7f1f0f45460944fbd8dfa7f37da06a4d13b3983cc90bb46963b"),
		1: _epochValidator(1,
			"0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b",
			"0x00ec7ef7780c9d151597924036262dd28dc60e1228f4da6fecf9d402cb3f3594"),
		2: _epochValidator(2,
			"0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b",
			"0x0036085c6c608e6d048505b04402568c36cce1e025722de44f9c3685a5c80fa6"),
		3: _epochValidator(3,
			"0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e",
			"0x005a7de495bcec04d3b5e74ae09ffe493a9dd06d7dcbf18c78455571e87d901a"),
		4: _epochValidator(4,
			"0x81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e",
			"0x004a28c193c65c91b7ebb5b5d14ffa7f75dc48ad4bc66de82f70fc55a2df1215"),
		5: _epochValidator(5,
			"0xab0bdda0f85f842f431beaccf1250bf1fd7ba51b4100fd64364b6401fda85bb0069b3e715b58819684e7fc0b10a72a34",
			"0x005856ab195b61df2ff5d6ab2fa36f30dab45e42cfa1aaef3ffd899f29bd8641"),
		6: _epochValidator(6,
			"0x9977f1c8b731a8d5558146bfb86caea26434f3c5878b589bf280a42c9159e700e9df0e4086296c20b011d2e78c27d373",
			"0x001c5d9bedbad1b7aff3b80e887e65b3357a695b70b6ee0625c2b2f6f86449f8"),
		7: _epochValidator(7,
			"0xa8d4c7c27795a725961317ef5953a7032ed6d83739db8b0e8a72353d1b8b4439427f7efa2c89caa03cc9f28f8cbab8ac",
			"0x001414bfc6dacca55f974ec910893c8617f9c99da897534c637b50e9fc695323"),
		8: _epochValidator(8,
			"0xa6d310dbbfab9a22450f59993f87a4ce5db6223f3b5f1f30d2c4ec718922d400e0b3c7741de8e59960f72411a0ee10a7",
			"0x00ed09b6181e6f97365e221e70aeebcb2604011d8c4326f3b98ce8d79b031ae8"),
		9: _epochValidator(9,
			"0x9893413c00283a3f9ed9fd9845dda1cea38228d22567f9541dccc357e54a2d6a6e204103c92564cbc05f4905ac7c493a",
			"0x001fe05baa70dd29ce85f694898bb6de3bcde158a825db56906b54141b2a728d"),
		10: _epochValidator(10,
			"0x876dd4705157eb66dc71bc2e07fb151ea53e1a62a0bb980a7ce72d15f58944a8a3752d754f52f4a60dbfc7b18169f268",
			"0x00aa2cfedd0160868d0901664e9d2eac1275dd658e109fabe11c7ad87a07fc0c"),
		11: _epochValidator(11,
			"0xaec922bd7a9b7b1dc21993133b586b0c3041c1e2e04b513e862227b9d7aecaf9444222f7e78282a449622ffc6278915d",
			"0x0076f08e6f40cf14992b7e4f524ea0cf7e1c6fd7dd5200b564c96fc099d601aa"),
		12: _epochValidator(12,
			"0x9314c6de0386635e2799af798884c2ea09c63b9f079e572acc00b06a7faccce501ea4dfc0b1a23b8603680a5e3481327",
			"0x004a581b2ef2b79652a19d3332f6574b0213ddbd179480edbf7ff490823fd5c7"),
		13: _epochValidator(13,
			"0x903e2989e7442ee0a8958d020507a8bd985d3974f5e8273093be00db3935f0500e141b252bd09e3728892c7a8443863c",
			"0x0040c37a4dafa560a7665394aa7502e113ecfbdb72c1ef92826db24601889b87"),
		14: _epochValidator(14,
			"0x84398f539a64cbe01cfcd8c485ea51cd6657b94df93ee9b5dc61e1f18f69da6ca9d4dba63c956a81c68d5d4d4277a60f",
			"0x0047381e2716b14a79e1f102669c615eb3542e9230ed7712b21f305ecc1a43d5"),
		15: _epochValidator(15,
			"0x872c61b4a7f8510ec809e5b023f5fdda2105d024c470ddbbeca4bc74e8280af0d178d749853e8f6a841083ac1b4db98f",
			"0x0020dd5f2223831fce8d1c8fd4148943c9917e1d3a92191651892dc56448451c"),
		16: _epochValidator(16,
			"0x8f467e5723deac7659e1ca273e28410cbaa6d495ab66ae77014f4cd21c64b6b5ab9987c9b5537fe0279bd063fe609be7",
			"0x00b24fc624e56a5ed42a9639691e27e34b783c7237030367bd17cbef65fa6ccf"),
		17: _epochValidator(17,
			"0x8dde8306920812b32def3b663f7c540b49180345d3bcb8d3770790b7dc80030ebc06497feebd1bcf017d918f00bfa88f",
			"0x0018e4071970526ed149970747c6b858307be8b60aa7440ad93c1f351af62923"),
		18: _epochValidator(18,
			"0xab8d3a9bcc160e518fac0756d3e192c74789588ed4a2b1debf0c78f78479ca8edb05b12ce21103076df6af4eb8756ff9",
			"0x00bb019106332edfed624b40e410561513e9fb9e285cbc56a450d499a2b13769"),
		19: _epochValidator(19,
			"0x8d5d3672a233db513df7ad1e8beafeae99a9f0199ed4d949bbedbb6f394030c0416bd99b910e14f73c65b6a11fe6b62e",
			"0x004218c29533321c9aae659d8b2148b87693d6b1eee8e119805e5298f8bf0a33"),
		20: _epochValidator(20,
			"0xa1c76af1545d7901214bb6be06be5d9e458f8e989c19373a920f0018327c83982f6a2ac138260b8def732cb366411ddc",
			"0x0004e3d99964ee8b0b6ed11833ba55fbf7bf80fe8f4e45c4d00a3d4ff6d73c0c"),
		21: _epochValidator(21,
			"0x8dd74e1bb5228fc1fca274fda02b971c1003a4f409bbdfbcfec6426bf2f52addcbbebccdbf45eee6ae11eb5b5ee7244d",
			"0x00037233059d7c629c79ddb7d94b0ef1275ebe55ed20fb80a414548be9ec890a"),
		22: _epochValidator(22,
			"0x954eb88ed1207f891dc3c28fa6cfdf8f53bf0ed3d838f3476c0900a61314d22d4f0a300da3cd010444dd5183e35a593c",
			"0x0056a7b95fd200d2997155b525eacda73baae3f3196a48fb9a513ddd1e7247c3"),
		23: _epochValidator(23,
			"0xaf344fce60dbd5fb850070e6e76a065e1a32485245ef4f413135a86ae703da88407c5d01c71f6bb06a151ff96cca7191",
			"0x005bdba6a856b0df016f8cbad0f9c02a517e2ff2f5db19187e6d1ba155d4b2e5"),
		24: _epochValidator(24,
			"0xae241af60691fda1cf8ca44d49573c55818c53b6141800cca2d488b9a3fba71c0f869179fff50c084657831fbeb42bf4",
			"0x000cc62d0bf911cfba5320da6e1d7407ff744427f74e855fc2444357788d6830"),
		25: _epochValidator(25,
			"0x96746aaba64dc87835ba709332f4d5d7837ada092b439c49d251aecf92aab5dc132e917bf6f59799bc093f976a7bc021",
			"0x006badd5d911c8565362da6e00dde8d2dda73fb9127d5ba26849ae0a0636172b"),
		26: _epochValidator(26,
			"0xb9d1d914df3d4565465c3fd52b5b96e637f9980570cabf5b5d4aadf5a329ac36ad672819d997e735f5052e28b1f0c104",
			"0x00f53dc973d5288e8070cf79ac0168443f3a2703e83f600e6197067aa02ca662"),
		27: _epochValidator(27,
			"0x963528adb5322c2e2c54dc296ffddd2861bb103cbf64646781dfa8a3c2d8a8eda7079d2b3e95600028c44365afbf8879",
			"0x00fa4e26953e907b1ed8032bdd02c9869dbbf521f3cb7bac1c8112ccf45c1d3a"),
		28: _epochValidator(28,
			"0xb245d63d3f9d8ea1807a629fcb1b328cb4d542f35a3d5bc478be0df389dddd712fc4c816ba3fede9a96320ae6b24a7d8",
			"0x00a68cdbfc1e865255d8e436d7bc7fc63c87b5c9c247c9e5de34d4fc26a1adc9"),
		29: _epochValidator(29,
			"0xa98ed496c2f464226500a6ce04602ff9ef133ed6316f372f6c744aee165149f7e578b12780e0eacec307ae6907351d99",
			"0x002f6d1f79f89a308365af4dbb8a850918db7844165b36e43c64e1a35b4af0b2"),
		30: _epochValidator(30,
			"0xae00fc3de831b09661a0ac02873c45c84cb2b58cffb6430a3f607e4c3fa1e0932397f11307cd169cdc6f79c463527260",
			"0x00e6ef2894304bc790c9e6b3a75815f10ceea391d8ebb9a27e07bf54360e9b3d"),
		31: _epochValidator(31,
			"0xa4855c83d868f772a579133d9f23818008417b743e8447e235d8eb78b1d8f8a9f63f98c551beb7de254400f89592314d",
			"0x0077c6a139204cbdaae840e0beb43b384c35182aabbc1104207b6a5a626fe75b"),
	}, nil
}

// ValidatorsWithoutBalanceProvider is a mock for eth2client.ValidatorsProvider with eth2client.ValidatorsWithoutBalanceProvider.
type ValidatorsWithoutBalanceProvider struct{}

// NewValidatorsWithoutBalanceProvider returns a mock validators provider.
func NewValidatorsWithoutBalanceProvider() eth2client.ValidatorsProvider {
	return &ValidatorsWithoutBalanceProvider{}
}

// Validators is a mock.
func (m *ValidatorsWithoutBalanceProvider) Validators(ctx context.Context, stateID string, validators []spec.ValidatorIndex) (map[spec.ValidatorIndex]*api.Validator, error) {
	return map[spec.ValidatorIndex]*api.Validator{
		0: _epochValidator(0,
			"0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
			"0x00fad2a6bfb0e7f1f0f45460944fbd8dfa7f37da06a4d13b3983cc90bb46963b"),
		1: _epochValidator(1,
			"0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b",
			"0x00ec7ef7780c9d151597924036262dd28dc60e1228f4da6fecf9d402cb3f3594"),
		2: _epochValidator(2,
			"0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b",
			"0x0036085c6c608e6d048505b04402568c36cce1e025722de44f9c3685a5c80fa6"),
		3: _epochValidator(3,
			"0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e",
			"0x005a7de495bcec04d3b5e74ae09ffe493a9dd06d7dcbf18c78455571e87d901a"),
		4: _epochValidator(4,
			"0x81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e",
			"0x004a28c193c65c91b7ebb5b5d14ffa7f75dc48ad4bc66de82f70fc55a2df1215"),
		5: _epochValidator(5,
			"0xab0bdda0f85f842f431beaccf1250bf1fd7ba51b4100fd64364b6401fda85bb0069b3e715b58819684e7fc0b10a72a34",
			"0x005856ab195b61df2ff5d6ab2fa36f30dab45e42cfa1aaef3ffd899f29bd8641"),
		6: _epochValidator(6,
			"0x9977f1c8b731a8d5558146bfb86caea26434f3c5878b589bf280a42c9159e700e9df0e4086296c20b011d2e78c27d373",
			"0x001c5d9bedbad1b7aff3b80e887e65b3357a695b70b6ee0625c2b2f6f86449f8"),
		7: _epochValidator(7,
			"0xa8d4c7c27795a725961317ef5953a7032ed6d83739db8b0e8a72353d1b8b4439427f7efa2c89caa03cc9f28f8cbab8ac",
			"0x001414bfc6dacca55f974ec910893c8617f9c99da897534c637b50e9fc695323"),
		8: _epochValidator(8,
			"0xa6d310dbbfab9a22450f59993f87a4ce5db6223f3b5f1f30d2c4ec718922d400e0b3c7741de8e59960f72411a0ee10a7",
			"0x00ed09b6181e6f97365e221e70aeebcb2604011d8c4326f3b98ce8d79b031ae8"),
		9: _epochValidator(9,
			"0x9893413c00283a3f9ed9fd9845dda1cea38228d22567f9541dccc357e54a2d6a6e204103c92564cbc05f4905ac7c493a",
			"0x001fe05baa70dd29ce85f694898bb6de3bcde158a825db56906b54141b2a728d"),
		10: _epochValidator(10,
			"0x876dd4705157eb66dc71bc2e07fb151ea53e1a62a0bb980a7ce72d15f58944a8a3752d754f52f4a60dbfc7b18169f268",
			"0x00aa2cfedd0160868d0901664e9d2eac1275dd658e109fabe11c7ad87a07fc0c"),
		11: _epochValidator(11,
			"0xaec922bd7a9b7b1dc21993133b586b0c3041c1e2e04b513e862227b9d7aecaf9444222f7e78282a449622ffc6278915d",
			"0x0076f08e6f40cf14992b7e4f524ea0cf7e1c6fd7dd5200b564c96fc099d601aa"),
		12: _epochValidator(12,
			"0x9314c6de0386635e2799af798884c2ea09c63b9f079e572acc00b06a7faccce501ea4dfc0b1a23b8603680a5e3481327",
			"0x004a581b2ef2b79652a19d3332f6574b0213ddbd179480edbf7ff490823fd5c7"),
		13: _epochValidator(13,
			"0x903e2989e7442ee0a8958d020507a8bd985d3974f5e8273093be00db3935f0500e141b252bd09e3728892c7a8443863c",
			"0x0040c37a4dafa560a7665394aa7502e113ecfbdb72c1ef92826db24601889b87"),
		14: _epochValidator(14,
			"0x84398f539a64cbe01cfcd8c485ea51cd6657b94df93ee9b5dc61e1f18f69da6ca9d4dba63c956a81c68d5d4d4277a60f",
			"0x0047381e2716b14a79e1f102669c615eb3542e9230ed7712b21f305ecc1a43d5"),
		15: _epochValidator(15,
			"0x872c61b4a7f8510ec809e5b023f5fdda2105d024c470ddbbeca4bc74e8280af0d178d749853e8f6a841083ac1b4db98f",
			"0x0020dd5f2223831fce8d1c8fd4148943c9917e1d3a92191651892dc56448451c"),
		16: _epochValidator(16,
			"0x8f467e5723deac7659e1ca273e28410cbaa6d495ab66ae77014f4cd21c64b6b5ab9987c9b5537fe0279bd063fe609be7",
			"0x00b24fc624e56a5ed42a9639691e27e34b783c7237030367bd17cbef65fa6ccf"),
		17: _epochValidator(17,
			"0x8dde8306920812b32def3b663f7c540b49180345d3bcb8d3770790b7dc80030ebc06497feebd1bcf017d918f00bfa88f",
			"0x0018e4071970526ed149970747c6b858307be8b60aa7440ad93c1f351af62923"),
		18: _epochValidator(18,
			"0xab8d3a9bcc160e518fac0756d3e192c74789588ed4a2b1debf0c78f78479ca8edb05b12ce21103076df6af4eb8756ff9",
			"0x00bb019106332edfed624b40e410561513e9fb9e285cbc56a450d499a2b13769"),
		19: _epochValidator(19,
			"0x8d5d3672a233db513df7ad1e8beafeae99a9f0199ed4d949bbedbb6f394030c0416bd99b910e14f73c65b6a11fe6b62e",
			"0x004218c29533321c9aae659d8b2148b87693d6b1eee8e119805e5298f8bf0a33"),
		20: _epochValidator(20,
			"0xa1c76af1545d7901214bb6be06be5d9e458f8e989c19373a920f0018327c83982f6a2ac138260b8def732cb366411ddc",
			"0x0004e3d99964ee8b0b6ed11833ba55fbf7bf80fe8f4e45c4d00a3d4ff6d73c0c"),
		21: _epochValidator(21,
			"0x8dd74e1bb5228fc1fca274fda02b971c1003a4f409bbdfbcfec6426bf2f52addcbbebccdbf45eee6ae11eb5b5ee7244d",
			"0x00037233059d7c629c79ddb7d94b0ef1275ebe55ed20fb80a414548be9ec890a"),
		22: _epochValidator(22,
			"0x954eb88ed1207f891dc3c28fa6cfdf8f53bf0ed3d838f3476c0900a61314d22d4f0a300da3cd010444dd5183e35a593c",
			"0x0056a7b95fd200d2997155b525eacda73baae3f3196a48fb9a513ddd1e7247c3"),
		23: _epochValidator(23,
			"0xaf344fce60dbd5fb850070e6e76a065e1a32485245ef4f413135a86ae703da88407c5d01c71f6bb06a151ff96cca7191",
			"0x005bdba6a856b0df016f8cbad0f9c02a517e2ff2f5db19187e6d1ba155d4b2e5"),
		24: _epochValidator(24,
			"0xae241af60691fda1cf8ca44d49573c55818c53b6141800cca2d488b9a3fba71c0f869179fff50c084657831fbeb42bf4",
			"0x000cc62d0bf911cfba5320da6e1d7407ff744427f74e855fc2444357788d6830"),
		25: _epochValidator(25,
			"0x96746aaba64dc87835ba709332f4d5d7837ada092b439c49d251aecf92aab5dc132e917bf6f59799bc093f976a7bc021",
			"0x006badd5d911c8565362da6e00dde8d2dda73fb9127d5ba26849ae0a0636172b"),
		26: _epochValidator(26,
			"0xb9d1d914df3d4565465c3fd52b5b96e637f9980570cabf5b5d4aadf5a329ac36ad672819d997e735f5052e28b1f0c104",
			"0x00f53dc973d5288e8070cf79ac0168443f3a2703e83f600e6197067aa02ca662"),
		27: _epochValidator(27,
			"0x963528adb5322c2e2c54dc296ffddd2861bb103cbf64646781dfa8a3c2d8a8eda7079d2b3e95600028c44365afbf8879",
			"0x00fa4e26953e907b1ed8032bdd02c9869dbbf521f3cb7bac1c8112ccf45c1d3a"),
		28: _epochValidator(28,
			"0xb245d63d3f9d8ea1807a629fcb1b328cb4d542f35a3d5bc478be0df389dddd712fc4c816ba3fede9a96320ae6b24a7d8",
			"0x00a68cdbfc1e865255d8e436d7bc7fc63c87b5c9c247c9e5de34d4fc26a1adc9"),
		29: _epochValidator(29,
			"0xa98ed496c2f464226500a6ce04602ff9ef133ed6316f372f6c744aee165149f7e578b12780e0eacec307ae6907351d99",
			"0x002f6d1f79f89a308365af4dbb8a850918db7844165b36e43c64e1a35b4af0b2"),
		30: _epochValidator(30,
			"0xae00fc3de831b09661a0ac02873c45c84cb2b58cffb6430a3f607e4c3fa1e0932397f11307cd169cdc6f79c463527260",
			"0x00e6ef2894304bc790c9e6b3a75815f10ceea391d8ebb9a27e07bf54360e9b3d"),
		31: _epochValidator(31,
			"0xa4855c83d868f772a579133d9f23818008417b743e8447e235d8eb78b1d8f8a9f63f98c551beb7de254400f89592314d",
			"0x0077c6a139204cbdaae840e0beb43b384c35182aabbc1104207b6a5a626fe75b"),
	}, nil
}

// ValidatorsByPubKey is a mock.
func (m *ValidatorsWithoutBalanceProvider) ValidatorsByPubKey(ctx context.Context, stateID string, validators []spec.BLSPubKey) (map[spec.ValidatorIndex]*api.Validator, error) {
	return map[spec.ValidatorIndex]*api.Validator{
		0: _epochValidator(0,
			"0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
			"0x00fad2a6bfb0e7f1f0f45460944fbd8dfa7f37da06a4d13b3983cc90bb46963b"),
		1: _epochValidator(1,
			"0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b",
			"0x00ec7ef7780c9d151597924036262dd28dc60e1228f4da6fecf9d402cb3f3594"),
		2: _epochValidator(2,
			"0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b",
			"0x0036085c6c608e6d048505b04402568c36cce1e025722de44f9c3685a5c80fa6"),
		3: _epochValidator(3,
			"0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e",
			"0x005a7de495bcec04d3b5e74ae09ffe493a9dd06d7dcbf18c78455571e87d901a"),
		4: _epochValidator(4,
			"0x81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e",
			"0x004a28c193c65c91b7ebb5b5d14ffa7f75dc48ad4bc66de82f70fc55a2df1215"),
		5: _epochValidator(5,
			"0xab0bdda0f85f842f431beaccf1250bf1fd7ba51b4100fd64364b6401fda85bb0069b3e715b58819684e7fc0b10a72a34",
			"0x005856ab195b61df2ff5d6ab2fa36f30dab45e42cfa1aaef3ffd899f29bd8641"),
		6: _epochValidator(6,
			"0x9977f1c8b731a8d5558146bfb86caea26434f3c5878b589bf280a42c9159e700e9df0e4086296c20b011d2e78c27d373",
			"0x001c5d9bedbad1b7aff3b80e887e65b3357a695b70b6ee0625c2b2f6f86449f8"),
		7: _epochValidator(7,
			"0xa8d4c7c27795a725961317ef5953a7032ed6d83739db8b0e8a72353d1b8b4439427f7efa2c89caa03cc9f28f8cbab8ac",
			"0x001414bfc6dacca55f974ec910893c8617f9c99da897534c637b50e9fc695323"),
		8: _epochValidator(8,
			"0xa6d310dbbfab9a22450f59993f87a4ce5db6223f3b5f1f30d2c4ec718922d400e0b3c7741de8e59960f72411a0ee10a7",
			"0x00ed09b6181e6f97365e221e70aeebcb2604011d8c4326f3b98ce8d79b031ae8"),
		9: _epochValidator(9,
			"0x9893413c00283a3f9ed9fd9845dda1cea38228d22567f9541dccc357e54a2d6a6e204103c92564cbc05f4905ac7c493a",
			"0x001fe05baa70dd29ce85f694898bb6de3bcde158a825db56906b54141b2a728d"),
		10: _epochValidator(10,
			"0x876dd4705157eb66dc71bc2e07fb151ea53e1a62a0bb980a7ce72d15f58944a8a3752d754f52f4a60dbfc7b18169f268",
			"0x00aa2cfedd0160868d0901664e9d2eac1275dd658e109fabe11c7ad87a07fc0c"),
		11: _epochValidator(11,
			"0xaec922bd7a9b7b1dc21993133b586b0c3041c1e2e04b513e862227b9d7aecaf9444222f7e78282a449622ffc6278915d",
			"0x0076f08e6f40cf14992b7e4f524ea0cf7e1c6fd7dd5200b564c96fc099d601aa"),
		12: _epochValidator(12,
			"0x9314c6de0386635e2799af798884c2ea09c63b9f079e572acc00b06a7faccce501ea4dfc0b1a23b8603680a5e3481327",
			"0x004a581b2ef2b79652a19d3332f6574b0213ddbd179480edbf7ff490823fd5c7"),
		13: _epochValidator(13,
			"0x903e2989e7442ee0a8958d020507a8bd985d3974f5e8273093be00db3935f0500e141b252bd09e3728892c7a8443863c",
			"0x0040c37a4dafa560a7665394aa7502e113ecfbdb72c1ef92826db24601889b87"),
		14: _epochValidator(14,
			"0x84398f539a64cbe01cfcd8c485ea51cd6657b94df93ee9b5dc61e1f18f69da6ca9d4dba63c956a81c68d5d4d4277a60f",
			"0x0047381e2716b14a79e1f102669c615eb3542e9230ed7712b21f305ecc1a43d5"),
		15: _epochValidator(15,
			"0x872c61b4a7f8510ec809e5b023f5fdda2105d024c470ddbbeca4bc74e8280af0d178d749853e8f6a841083ac1b4db98f",
			"0x0020dd5f2223831fce8d1c8fd4148943c9917e1d3a92191651892dc56448451c"),
		16: _epochValidator(16,
			"0x8f467e5723deac7659e1ca273e28410cbaa6d495ab66ae77014f4cd21c64b6b5ab9987c9b5537fe0279bd063fe609be7",
			"0x00b24fc624e56a5ed42a9639691e27e34b783c7237030367bd17cbef65fa6ccf"),
		17: _epochValidator(17,
			"0x8dde8306920812b32def3b663f7c540b49180345d3bcb8d3770790b7dc80030ebc06497feebd1bcf017d918f00bfa88f",
			"0x0018e4071970526ed149970747c6b858307be8b60aa7440ad93c1f351af62923"),
		18: _epochValidator(18,
			"0xab8d3a9bcc160e518fac0756d3e192c74789588ed4a2b1debf0c78f78479ca8edb05b12ce21103076df6af4eb8756ff9",
			"0x00bb019106332edfed624b40e410561513e9fb9e285cbc56a450d499a2b13769"),
		19: _epochValidator(19,
			"0x8d5d3672a233db513df7ad1e8beafeae99a9f0199ed4d949bbedbb6f394030c0416bd99b910e14f73c65b6a11fe6b62e",
			"0x004218c29533321c9aae659d8b2148b87693d6b1eee8e119805e5298f8bf0a33"),
		20: _epochValidator(20,
			"0xa1c76af1545d7901214bb6be06be5d9e458f8e989c19373a920f0018327c83982f6a2ac138260b8def732cb366411ddc",
			"0x0004e3d99964ee8b0b6ed11833ba55fbf7bf80fe8f4e45c4d00a3d4ff6d73c0c"),
		21: _epochValidator(21,
			"0x8dd74e1bb5228fc1fca274fda02b971c1003a4f409bbdfbcfec6426bf2f52addcbbebccdbf45eee6ae11eb5b5ee7244d",
			"0x00037233059d7c629c79ddb7d94b0ef1275ebe55ed20fb80a414548be9ec890a"),
		22: _epochValidator(22,
			"0x954eb88ed1207f891dc3c28fa6cfdf8f53bf0ed3d838f3476c0900a61314d22d4f0a300da3cd010444dd5183e35a593c",
			"0x0056a7b95fd200d2997155b525eacda73baae3f3196a48fb9a513ddd1e7247c3"),
		23: _epochValidator(23,
			"0xaf344fce60dbd5fb850070e6e76a065e1a32485245ef4f413135a86ae703da88407c5d01c71f6bb06a151ff96cca7191",
			"0x005bdba6a856b0df016f8cbad0f9c02a517e2ff2f5db19187e6d1ba155d4b2e5"),
		24: _epochValidator(24,
			"0xae241af60691fda1cf8ca44d49573c55818c53b6141800cca2d488b9a3fba71c0f869179fff50c084657831fbeb42bf4",
			"0x000cc62d0bf911cfba5320da6e1d7407ff744427f74e855fc2444357788d6830"),
		25: _epochValidator(25,
			"0x96746aaba64dc87835ba709332f4d5d7837ada092b439c49d251aecf92aab5dc132e917bf6f59799bc093f976a7bc021",
			"0x006badd5d911c8565362da6e00dde8d2dda73fb9127d5ba26849ae0a0636172b"),
		26: _epochValidator(26,
			"0xb9d1d914df3d4565465c3fd52b5b96e637f9980570cabf5b5d4aadf5a329ac36ad672819d997e735f5052e28b1f0c104",
			"0x00f53dc973d5288e8070cf79ac0168443f3a2703e83f600e6197067aa02ca662"),
		27: _epochValidator(27,
			"0x963528adb5322c2e2c54dc296ffddd2861bb103cbf64646781dfa8a3c2d8a8eda7079d2b3e95600028c44365afbf8879",
			"0x00fa4e26953e907b1ed8032bdd02c9869dbbf521f3cb7bac1c8112ccf45c1d3a"),
		28: _epochValidator(28,
			"0xb245d63d3f9d8ea1807a629fcb1b328cb4d542f35a3d5bc478be0df389dddd712fc4c816ba3fede9a96320ae6b24a7d8",
			"0x00a68cdbfc1e865255d8e436d7bc7fc63c87b5c9c247c9e5de34d4fc26a1adc9"),
		29: _epochValidator(29,
			"0xa98ed496c2f464226500a6ce04602ff9ef133ed6316f372f6c744aee165149f7e578b12780e0eacec307ae6907351d99",
			"0x002f6d1f79f89a308365af4dbb8a850918db7844165b36e43c64e1a35b4af0b2"),
		30: _epochValidator(30,
			"0xae00fc3de831b09661a0ac02873c45c84cb2b58cffb6430a3f607e4c3fa1e0932397f11307cd169cdc6f79c463527260",
			"0x00e6ef2894304bc790c9e6b3a75815f10ceea391d8ebb9a27e07bf54360e9b3d"),
		31: _epochValidator(31,
			"0xa4855c83d868f772a579133d9f23818008417b743e8447e235d8eb78b1d8f8a9f63f98c551beb7de254400f89592314d",
			"0x0077c6a139204cbdaae840e0beb43b384c35182aabbc1104207b6a5a626fe75b"),
	}, nil
}

// ValidatorsWithoutBalance is a mock.
func (m *ValidatorsWithoutBalanceProvider) ValidatorsWithoutBalance(ctx context.Context, stateID string, validators []spec.ValidatorIndex) (map[spec.ValidatorIndex]*api.Validator, error) {
	res := map[spec.ValidatorIndex]*api.Validator{
		0: _epochValidator(0,
			"0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
			"0x00fad2a6bfb0e7f1f0f45460944fbd8dfa7f37da06a4d13b3983cc90bb46963b"),
		1: _epochValidator(1,
			"0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b",
			"0x00ec7ef7780c9d151597924036262dd28dc60e1228f4da6fecf9d402cb3f3594"),
		2: _epochValidator(2,
			"0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b",
			"0x0036085c6c608e6d048505b04402568c36cce1e025722de44f9c3685a5c80fa6"),
		3: _epochValidator(3,
			"0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e",
			"0x005a7de495bcec04d3b5e74ae09ffe493a9dd06d7dcbf18c78455571e87d901a"),
		4: _epochValidator(4,
			"0x81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e",
			"0x004a28c193c65c91b7ebb5b5d14ffa7f75dc48ad4bc66de82f70fc55a2df1215"),
		5: _epochValidator(5,
			"0xab0bdda0f85f842f431beaccf1250bf1fd7ba51b4100fd64364b6401fda85bb0069b3e715b58819684e7fc0b10a72a34",
			"0x005856ab195b61df2ff5d6ab2fa36f30dab45e42cfa1aaef3ffd899f29bd8641"),
		6: _epochValidator(6,
			"0x9977f1c8b731a8d5558146bfb86caea26434f3c5878b589bf280a42c9159e700e9df0e4086296c20b011d2e78c27d373",
			"0x001c5d9bedbad1b7aff3b80e887e65b3357a695b70b6ee0625c2b2f6f86449f8"),
		7: _epochValidator(7,
			"0xa8d4c7c27795a725961317ef5953a7032ed6d83739db8b0e8a72353d1b8b4439427f7efa2c89caa03cc9f28f8cbab8ac",
			"0x001414bfc6dacca55f974ec910893c8617f9c99da897534c637b50e9fc695323"),
		8: _epochValidator(8,
			"0xa6d310dbbfab9a22450f59993f87a4ce5db6223f3b5f1f30d2c4ec718922d400e0b3c7741de8e59960f72411a0ee10a7",
			"0x00ed09b6181e6f97365e221e70aeebcb2604011d8c4326f3b98ce8d79b031ae8"),
		9: _epochValidator(9,
			"0x9893413c00283a3f9ed9fd9845dda1cea38228d22567f9541dccc357e54a2d6a6e204103c92564cbc05f4905ac7c493a",
			"0x001fe05baa70dd29ce85f694898bb6de3bcde158a825db56906b54141b2a728d"),
		10: _epochValidator(10,
			"0x876dd4705157eb66dc71bc2e07fb151ea53e1a62a0bb980a7ce72d15f58944a8a3752d754f52f4a60dbfc7b18169f268",
			"0x00aa2cfedd0160868d0901664e9d2eac1275dd658e109fabe11c7ad87a07fc0c"),
		11: _epochValidator(11,
			"0xaec922bd7a9b7b1dc21993133b586b0c3041c1e2e04b513e862227b9d7aecaf9444222f7e78282a449622ffc6278915d",
			"0x0076f08e6f40cf14992b7e4f524ea0cf7e1c6fd7dd5200b564c96fc099d601aa"),
		12: _epochValidator(12,
			"0x9314c6de0386635e2799af798884c2ea09c63b9f079e572acc00b06a7faccce501ea4dfc0b1a23b8603680a5e3481327",
			"0x004a581b2ef2b79652a19d3332f6574b0213ddbd179480edbf7ff490823fd5c7"),
		13: _epochValidator(13,
			"0x903e2989e7442ee0a8958d020507a8bd985d3974f5e8273093be00db3935f0500e141b252bd09e3728892c7a8443863c",
			"0x0040c37a4dafa560a7665394aa7502e113ecfbdb72c1ef92826db24601889b87"),
		14: _epochValidator(14,
			"0x84398f539a64cbe01cfcd8c485ea51cd6657b94df93ee9b5dc61e1f18f69da6ca9d4dba63c956a81c68d5d4d4277a60f",
			"0x0047381e2716b14a79e1f102669c615eb3542e9230ed7712b21f305ecc1a43d5"),
		15: _epochValidator(15,
			"0x872c61b4a7f8510ec809e5b023f5fdda2105d024c470ddbbeca4bc74e8280af0d178d749853e8f6a841083ac1b4db98f",
			"0x0020dd5f2223831fce8d1c8fd4148943c9917e1d3a92191651892dc56448451c"),
		16: _epochValidator(16,
			"0x8f467e5723deac7659e1ca273e28410cbaa6d495ab66ae77014f4cd21c64b6b5ab9987c9b5537fe0279bd063fe609be7",
			"0x00b24fc624e56a5ed42a9639691e27e34b783c7237030367bd17cbef65fa6ccf"),
		17: _epochValidator(17,
			"0x8dde8306920812b32def3b663f7c540b49180345d3bcb8d3770790b7dc80030ebc06497feebd1bcf017d918f00bfa88f",
			"0x0018e4071970526ed149970747c6b858307be8b60aa7440ad93c1f351af62923"),
		18: _epochValidator(18,
			"0xab8d3a9bcc160e518fac0756d3e192c74789588ed4a2b1debf0c78f78479ca8edb05b12ce21103076df6af4eb8756ff9",
			"0x00bb019106332edfed624b40e410561513e9fb9e285cbc56a450d499a2b13769"),
		19: _epochValidator(19,
			"0x8d5d3672a233db513df7ad1e8beafeae99a9f0199ed4d949bbedbb6f394030c0416bd99b910e14f73c65b6a11fe6b62e",
			"0x004218c29533321c9aae659d8b2148b87693d6b1eee8e119805e5298f8bf0a33"),
		20: _epochValidator(20,
			"0xa1c76af1545d7901214bb6be06be5d9e458f8e989c19373a920f0018327c83982f6a2ac138260b8def732cb366411ddc",
			"0x0004e3d99964ee8b0b6ed11833ba55fbf7bf80fe8f4e45c4d00a3d4ff6d73c0c"),
		21: _epochValidator(21,
			"0x8dd74e1bb5228fc1fca274fda02b971c1003a4f409bbdfbcfec6426bf2f52addcbbebccdbf45eee6ae11eb5b5ee7244d",
			"0x00037233059d7c629c79ddb7d94b0ef1275ebe55ed20fb80a414548be9ec890a"),
		22: _epochValidator(22,
			"0x954eb88ed1207f891dc3c28fa6cfdf8f53bf0ed3d838f3476c0900a61314d22d4f0a300da3cd010444dd5183e35a593c",
			"0x0056a7b95fd200d2997155b525eacda73baae3f3196a48fb9a513ddd1e7247c3"),
		23: _epochValidator(23,
			"0xaf344fce60dbd5fb850070e6e76a065e1a32485245ef4f413135a86ae703da88407c5d01c71f6bb06a151ff96cca7191",
			"0x005bdba6a856b0df016f8cbad0f9c02a517e2ff2f5db19187e6d1ba155d4b2e5"),
		24: _epochValidator(24,
			"0xae241af60691fda1cf8ca44d49573c55818c53b6141800cca2d488b9a3fba71c0f869179fff50c084657831fbeb42bf4",
			"0x000cc62d0bf911cfba5320da6e1d7407ff744427f74e855fc2444357788d6830"),
		25: _epochValidator(25,
			"0x96746aaba64dc87835ba709332f4d5d7837ada092b439c49d251aecf92aab5dc132e917bf6f59799bc093f976a7bc021",
			"0x006badd5d911c8565362da6e00dde8d2dda73fb9127d5ba26849ae0a0636172b"),
		26: _epochValidator(26,
			"0xb9d1d914df3d4565465c3fd52b5b96e637f9980570cabf5b5d4aadf5a329ac36ad672819d997e735f5052e28b1f0c104",
			"0x00f53dc973d5288e8070cf79ac0168443f3a2703e83f600e6197067aa02ca662"),
		27: _epochValidator(27,
			"0x963528adb5322c2e2c54dc296ffddd2861bb103cbf64646781dfa8a3c2d8a8eda7079d2b3e95600028c44365afbf8879",
			"0x00fa4e26953e907b1ed8032bdd02c9869dbbf521f3cb7bac1c8112ccf45c1d3a"),
		28: _epochValidator(28,
			"0xb245d63d3f9d8ea1807a629fcb1b328cb4d542f35a3d5bc478be0df389dddd712fc4c816ba3fede9a96320ae6b24a7d8",
			"0x00a68cdbfc1e865255d8e436d7bc7fc63c87b5c9c247c9e5de34d4fc26a1adc9"),
		29: _epochValidator(29,
			"0xa98ed496c2f464226500a6ce04602ff9ef133ed6316f372f6c744aee165149f7e578b12780e0eacec307ae6907351d99",
			"0x002f6d1f79f89a308365af4dbb8a850918db7844165b36e43c64e1a35b4af0b2"),
		30: _epochValidator(30,
			"0xae00fc3de831b09661a0ac02873c45c84cb2b58cffb6430a3f607e4c3fa1e0932397f11307cd169cdc6f79c463527260",
			"0x00e6ef2894304bc790c9e6b3a75815f10ceea391d8ebb9a27e07bf54360e9b3d"),
		31: _epochValidator(31,
			"0xa4855c83d868f772a579133d9f23818008417b743e8447e235d8eb78b1d8f8a9f63f98c551beb7de254400f89592314d",
			"0x0077c6a139204cbdaae840e0beb43b384c35182aabbc1104207b6a5a626fe75b"),
	}

	for _, validator := range res {
		validator.Balance = 0
	}

	return res, nil
}
