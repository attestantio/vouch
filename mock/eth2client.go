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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
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
