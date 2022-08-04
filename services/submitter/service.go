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

package submitter

import (
	"context"

	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
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
	SubmitBeaconBlock(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error
}

// // BlindedBeaconBlockSubmitter is the interface for a submitter of blinded beacon blocks.
// type BlindedBeaconBlockSubmitter interface {
// 	// SubmitBlindedBeaconBlock submits a blinded block.
// 	SubmitBlindedBeaconBlock(ctx context.Context, block *api.VersionedSignedBlindedBeaconBlock) error
// }

// BeaconCommitteeSubscriptionsSubmitter is the interface for a submitter of beacon committee subscriptions.
type BeaconCommitteeSubscriptionsSubmitter interface {
	// SubmitBeaconCommitteeSubscription submits a batch of beacon committee subscriptions.
	SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*apiv1.BeaconCommitteeSubscription) error
}

// AggregateAttestationsSubmitter is the interface for a submitter of aggregate attestations.
type AggregateAttestationsSubmitter interface {
	// SubmitAggregateAttestations submits aggregate attestations.
	SubmitAggregateAttestations(ctx context.Context, aggregateAttestations []*phase0.SignedAggregateAndProof) error
}

// ProposalPreparationsSubmitter is the interface for a submitter of proposal preparations.
type ProposalPreparationsSubmitter interface {
	// SubmitProposalPreparations submits proposal preparations.
	SubmitProposalPreparations(ctx context.Context, preparations []*apiv1.ProposalPreparation) error
}

// SyncCommitteeMessagesSubmitter is the interface for a submitter of sync committee messages.
type SyncCommitteeMessagesSubmitter interface {
	// SubmitSyncCommitteeMessages submits sync committee messages.
	SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error
}

// SyncCommitteeSubscriptionsSubmitter is the interface for a submitter of sync committee subscriptions.
type SyncCommitteeSubscriptionsSubmitter interface {
	// SubmitSyncCommitteeSubscription submits a batch of sync committee subscriptions.
	SubmitSyncCommitteeSubscriptions(ctx context.Context, subscriptions []*apiv1.SyncCommitteeSubscription) error
}

// SyncCommitteeContributionsSubmitter is the interface for a submitter of sync committee contributions.
type SyncCommitteeContributionsSubmitter interface {
	// SubmitSyncCommitteeContributions submits sync committee contributions.
	SubmitSyncCommitteeContributions(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error
}
