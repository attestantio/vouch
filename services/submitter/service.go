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

	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// Service is the submitter service.
type Service interface{}

// AttestationsSubmitter is the interface for a submitter of attestations.
type AttestationsSubmitter interface {
	// SubmitAttestations submits multiple attestations.
	SubmitAttestations(ctx context.Context, attestations []*phase0.Attestation) error
}

// BeaconBlockSubmitter is the interface for a submitter of beacon blocks.
type BeaconBlockSubmitter interface {
	// SubmitBeaconBlock submits a block.
	SubmitBeaconBlock(ctx context.Context, block *phase0.SignedBeaconBlock) error
}

// BeaconCommitteeSubscriptionsSubmitter is the interface for a submitter of beacon committee subscriptions.
type BeaconCommitteeSubscriptionsSubmitter interface {
	// SubmitBeaconCommitteeSubscription submits a batch of beacon committee subscriptions.
	SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*api.BeaconCommitteeSubscription) error
}

// AggregateAttestationsSubmitter is the interface for a submitter of aggregate attestations.
type AggregateAttestationsSubmitter interface {
	// SubmitAggregateAttestations submits aggregate attestations.
	SubmitAggregateAttestations(ctx context.Context, aggregateAttestations []*phase0.SignedAggregateAndProof) error
}
