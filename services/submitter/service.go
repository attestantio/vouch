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

package submitter

import (
	"context"

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
)

// Service is the submitter service.
type Service interface{}

// AttestationSubmitter is the interface for a submitter of attestations.
type AttestationSubmitter interface {
	// SubmitAttestation submits an attestation.
	SubmitAttestation(ctx context.Context, block *spec.Attestation) error
}

// BeaconBlockSubmitter is the interface for a submitter of beacon blocks.
type BeaconBlockSubmitter interface {
	// SubmitBeaconBlock submits a block.
	SubmitBeaconBlock(ctx context.Context, block *spec.SignedBeaconBlock) error
}

// BeaconCommitteeSubscription is a subscription for a particular beacon committee at a given time.
type BeaconCommitteeSubscription struct {
	Slot            uint64
	CommitteeIndex  uint64
	CommitteeSize   uint64
	ValidatorIndex  uint64
	ValidatorPubKey []byte
	Aggregate       bool
	Signature       []byte
}

// BeaconCommitteeSubscriptionsSubmitter is the interface for a submitter of beacon committee subscriptions.
type BeaconCommitteeSubscriptionsSubmitter interface {
	// SubmitBeaconCommitteeSubscription submits a batch of beacon committee subscriptions.
	SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*BeaconCommitteeSubscription) error
}

// AggregateAttestationSubmitter is the interface for a submitter of aggregate attestations.
type AggregateAttestationSubmitter interface {
	// SubmitAggregateAttestation submits an aggregate attestation.
	SubmitAggregateAttestation(ctx context.Context, aggregateAttestation *spec.SignedAggregateAndProof) error
}
