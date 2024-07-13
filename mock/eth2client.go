// Copyright © 2020 - 2023 Attestant Limited.
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
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
)

// GenesisProvider is a mock for eth2client.GenesisProvider.
type GenesisProvider struct {
	genesisTime time.Time
}

// NewGenesisProvider returns a mock genesis provider with the provided value.
func NewGenesisProvider(genesisTime time.Time) eth2client.GenesisProvider {
	return &GenesisProvider{
		genesisTime: genesisTime,
	}
}

// Genesis is a mock.
func (m *GenesisProvider) Genesis(_ context.Context, _ *api.GenesisOpts) (*api.Response[*apiv1.Genesis], error) {
	return &api.Response[*apiv1.Genesis]{
		Data: &apiv1.Genesis{
			GenesisTime: m.genesisTime,
		},
	}, nil
}

// FarFutureEpochProvider is a mock for eth2client.FarFutureEpochProvider.
type FarFutureEpochProvider struct {
	farFutureEpoch phase0.Epoch
}

// NewFarFutureEpochProvider returns a mock far future epoch provider with the provided value.
func NewFarFutureEpochProvider(farFutureEpoch phase0.Epoch) eth2client.FarFutureEpochProvider {
	return &FarFutureEpochProvider{
		farFutureEpoch: farFutureEpoch,
	}
}

// FarFutureEpoch is a mock.
func (m *FarFutureEpochProvider) FarFutureEpoch(_ context.Context) (phase0.Epoch, error) {
	return m.farFutureEpoch, nil
}

// ProposerDutiesProvider is a mock for eth2client.ProposerDutiesProvider.
type ProposerDutiesProvider struct{}

// NewProposerDutiesProvider returns a mock proposer duties provider.
func NewProposerDutiesProvider() eth2client.ProposerDutiesProvider {
	return &ProposerDutiesProvider{}
}

// ProposerDuties is a mock.
func (*ProposerDutiesProvider) ProposerDuties(_ context.Context,
	_ *api.ProposerDutiesOpts,
) (
	*api.Response[[]*apiv1.ProposerDuty],
	error,
) {
	return &api.Response[[]*apiv1.ProposerDuty]{
		Data:     make([]*apiv1.ProposerDuty, 0),
		Metadata: make(map[string]any),
	}, nil
}

// AttesterDutiesProvider is a mock for eth2client.AttesterDutiesProvider.
type AttesterDutiesProvider struct{}

// NewAttesterDutiesProvider returns a mock attester duties provider.
func NewAttesterDutiesProvider() eth2client.AttesterDutiesProvider {
	return &AttesterDutiesProvider{}
}

// AttesterDuties is a mock.
func (*AttesterDutiesProvider) AttesterDuties(_ context.Context,
	_ *api.AttesterDutiesOpts,
) (
	*api.Response[[]*apiv1.AttesterDuty],
	error,
) {
	return &api.Response[[]*apiv1.AttesterDuty]{
		Data:     make([]*apiv1.AttesterDuty, 0),
		Metadata: make(map[string]any),
	}, nil
}

// SyncCommitteeDutiesProvider is a mock for eth2client.SyncCommitteeDutiesProvider.
type SyncCommitteeDutiesProvider struct{}

// NewSyncCommitteeDutiesProvider returns a mock attester duties provider.
func NewSyncCommitteeDutiesProvider() eth2client.SyncCommitteeDutiesProvider {
	return &SyncCommitteeDutiesProvider{}
}

// SyncCommitteeDuties is a mock.
func (*SyncCommitteeDutiesProvider) SyncCommitteeDuties(_ context.Context,
	_ *api.SyncCommitteeDutiesOpts,
) (
	*api.Response[[]*apiv1.SyncCommitteeDuty],
	error,
) {
	return &api.Response[[]*apiv1.SyncCommitteeDuty]{
		Data:     make([]*apiv1.SyncCommitteeDuty, 0),
		Metadata: make(map[string]any),
	}, nil
}

// SyncCommitteeSubscriptionsSubmitter is a mock for eth2client.SyncCommitteeSubscriptionsSubmitter.
type SyncCommitteeSubscriptionsSubmitter struct{}

// NewSyncCommitteeSubscriptionsSubmitter returns a mock attester duties submitter.
func NewSyncCommitteeSubscriptionsSubmitter() eth2client.SyncCommitteeSubscriptionsSubmitter {
	return &SyncCommitteeSubscriptionsSubmitter{}
}

// SubmitSyncCommitteeSubscriptions is a mock.
func (*SyncCommitteeSubscriptionsSubmitter) SubmitSyncCommitteeSubscriptions(_ context.Context, _ []*apiv1.SyncCommitteeSubscription) error {
	return nil
}

// ErroringSyncCommitteeSubscriptionsSubmitter is a mock for eth2client.SyncCommitteeSubscriptionsSubmitter.
type ErroringSyncCommitteeSubscriptionsSubmitter struct{}

// NewErroringSyncCommitteeSubscriptionsSubmitter returns a mock attester duties submitter.
func NewErroringSyncCommitteeSubscriptionsSubmitter() eth2client.SyncCommitteeSubscriptionsSubmitter {
	return &ErroringSyncCommitteeSubscriptionsSubmitter{}
}

// SubmitSyncCommitteeSubscriptions is a mock.
func (*ErroringSyncCommitteeSubscriptionsSubmitter) SubmitSyncCommitteeSubscriptions(_ context.Context, _ []*apiv1.SyncCommitteeSubscription) error {
	return errors.New("error")
}

// SleepySyncCommitteeSubscriptionsSubmitter is a mock for eth2client.SyncCommitteeSubscriptionsSubmitter.
type SleepySyncCommitteeSubscriptionsSubmitter struct {
	wait time.Duration
	next eth2client.SyncCommitteeSubscriptionsSubmitter
}

// NewSleepySyncCommitteeSubscriptionsSubmitter returns a mock sync committee subscriptions submitter.
func NewSleepySyncCommitteeSubscriptionsSubmitter(wait time.Duration, next eth2client.SyncCommitteeSubscriptionsSubmitter) eth2client.SyncCommitteeSubscriptionsSubmitter {
	return &SleepySyncCommitteeSubscriptionsSubmitter{
		wait: wait,
		next: next,
	}
}

// SubmitSyncCommitteeSubscriptions is a mock.
func (m *SleepySyncCommitteeSubscriptionsSubmitter) SubmitSyncCommitteeSubscriptions(ctx context.Context, subscriptions []*apiv1.SyncCommitteeSubscription) error {
	time.Sleep(m.wait)
	return m.next.SubmitSyncCommitteeSubscriptions(ctx, subscriptions)
}

// SyncCommitteeMessagesSubmitter is a mock for eth2client.SyncCommitteeMessagesSubmitter.
type SyncCommitteeMessagesSubmitter struct{}

// NewSyncCommitteeMessagesSubmitter returns a mock attester duties submitter.
func NewSyncCommitteeMessagesSubmitter() eth2client.SyncCommitteeMessagesSubmitter {
	return &SyncCommitteeMessagesSubmitter{}
}

// SubmitSyncCommitteeMessages submits sync committee messages.
func (*SyncCommitteeMessagesSubmitter) SubmitSyncCommitteeMessages(_ context.Context, _ []*altair.SyncCommitteeMessage) error {
	return nil
}

// ErroringSyncCommitteeMessagesSubmitter is a mock for eth2client.SyncCommitteeMessagesSubmitter.
type ErroringSyncCommitteeMessagesSubmitter struct{}

// NewErroringSyncCommitteeMessagesSubmitter returns a mock attester duties submitter.
func NewErroringSyncCommitteeMessagesSubmitter() eth2client.SyncCommitteeMessagesSubmitter {
	return &ErroringSyncCommitteeMessagesSubmitter{}
}

// SubmitSyncCommitteeMessages submits sync committee messages.
func (*ErroringSyncCommitteeMessagesSubmitter) SubmitSyncCommitteeMessages(_ context.Context, _ []*altair.SyncCommitteeMessage) error {
	return errors.New("error")
}

// SleepySyncCommitteeMessagesSubmitter is a mock for eth2client.SyncCommitteeMessagesSubmitter.
type SleepySyncCommitteeMessagesSubmitter struct {
	wait time.Duration
	next eth2client.SyncCommitteeMessagesSubmitter
}

// NewSleepySyncCommitteeMessagesSubmitter returns a mock sync committee messages submitter.
func NewSleepySyncCommitteeMessagesSubmitter(wait time.Duration, next eth2client.SyncCommitteeMessagesSubmitter) eth2client.SyncCommitteeMessagesSubmitter {
	return &SleepySyncCommitteeMessagesSubmitter{
		wait: wait,
		next: next,
	}
}

// SubmitSyncCommitteeMessages is a mock.
func (m *SleepySyncCommitteeMessagesSubmitter) SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
	time.Sleep(m.wait)
	return m.next.SubmitSyncCommitteeMessages(ctx, messages)
}

// SyncCommitteeContributionsSubmitter is a mock for eth2client.SyncCommitteeContributionsSubmitter.
type SyncCommitteeContributionsSubmitter struct{}

// NewSyncCommitteeContributionsSubmitter returns a mock attester duties submitter.
func NewSyncCommitteeContributionsSubmitter() eth2client.SyncCommitteeContributionsSubmitter {
	return &SyncCommitteeContributionsSubmitter{}
}

// SubmitSyncCommitteeContributions submits sync committee contributions.
func (*SyncCommitteeContributionsSubmitter) SubmitSyncCommitteeContributions(_ context.Context, _ []*altair.SignedContributionAndProof) error {
	return nil
}

// ErroringSyncCommitteeContributionsSubmitter is a mock for eth2client.SyncCommitteeContributionsSubmitter.
type ErroringSyncCommitteeContributionsSubmitter struct{}

// NewErroringSyncCommitteeContributionsSubmitter returns a mock attester duties submitter.
func NewErroringSyncCommitteeContributionsSubmitter() eth2client.SyncCommitteeContributionsSubmitter {
	return &ErroringSyncCommitteeContributionsSubmitter{}
}

// SubmitSyncCommitteeContributions submits sync committee contributions.
func (*ErroringSyncCommitteeContributionsSubmitter) SubmitSyncCommitteeContributions(_ context.Context, _ []*altair.SignedContributionAndProof) error {
	return errors.New("error")
}

// SleepySyncCommitteeContributionsSubmitter is a mock for eth2client.SyncCommitteeContributionsSubmitter.
type SleepySyncCommitteeContributionsSubmitter struct {
	wait time.Duration
	next eth2client.SyncCommitteeContributionsSubmitter
}

// NewSleepySyncCommitteeContributionsSubmitter returns a mock contribution and proofs submitter.
func NewSleepySyncCommitteeContributionsSubmitter(wait time.Duration, next eth2client.SyncCommitteeContributionsSubmitter) eth2client.SyncCommitteeContributionsSubmitter {
	return &SleepySyncCommitteeContributionsSubmitter{
		wait: wait,
		next: next,
	}
}

// SubmitSyncCommitteeContributions is a mock.
func (m *SleepySyncCommitteeContributionsSubmitter) SubmitSyncCommitteeContributions(ctx context.Context, proofs []*altair.SignedContributionAndProof) error {
	time.Sleep(m.wait)
	return m.next.SubmitSyncCommitteeContributions(ctx, proofs)
}

// EventsProvider is a mock for eth2client.EventsProvider.
type EventsProvider struct{}

// NewEventsProvider returns a mock events provider.
func NewEventsProvider() eth2client.EventsProvider {
	return &EventsProvider{}
}

// Events is a mock.
func (*EventsProvider) Events(_ context.Context, _ []string, _ eth2client.EventHandlerFunc) error {
	return nil
}

// ErroringEventsProvider is a mock for eth2client.EventsProvider.
type ErroringEventsProvider struct{}

// NewErroringEventsProvider returns a mock events provider.
func NewErroringEventsProvider() eth2client.EventsProvider {
	return &ErroringEventsProvider{}
}

// Events submits sync committee contributions.
func (*ErroringEventsProvider) Events(_ context.Context, _ []string, _ eth2client.EventHandlerFunc) error {
	return errors.New("error")
}

// AttestationsSubmitter is a mock for eth2client.AttestationsSubmitter.
type AttestationsSubmitter struct{}

// NewAttestationsSubmitter returns a mock attestations submitter.
func NewAttestationsSubmitter() eth2client.AttestationsSubmitter {
	return &AttestationsSubmitter{}
}

// SubmitAttestations is a mock.
func (*AttestationsSubmitter) SubmitAttestations(_ context.Context, _ []*phase0.Attestation) error {
	return nil
}

// ErroringAttestationsSubmitter is a mock for eth2client.AttestationsSubmitter that returns errors.
type ErroringAttestationsSubmitter struct{}

// NewErroringAttestationsSubmitter returns a mock attestation submitter.
func NewErroringAttestationsSubmitter() eth2client.AttestationsSubmitter {
	return &ErroringAttestationsSubmitter{}
}

// SubmitAttestations is a mock.
func (*ErroringAttestationsSubmitter) SubmitAttestations(_ context.Context, _ []*phase0.Attestation) error {
	return errors.New("error")
}

// SleepyAttestationsSubmitter is a mock for eth2client.AttestationsSubmitter.
type SleepyAttestationsSubmitter struct {
	wait time.Duration
	next eth2client.AttestationsSubmitter
}

// NewSleepyAttestationsSubmitter returns a mock attestations submitter.
func NewSleepyAttestationsSubmitter(wait time.Duration, next eth2client.AttestationsSubmitter) eth2client.AttestationsSubmitter {
	return &SleepyAttestationsSubmitter{
		wait: wait,
		next: next,
	}
}

// SubmitAttestations is a mock.
func (m *SleepyAttestationsSubmitter) SubmitAttestations(ctx context.Context, attestations []*phase0.Attestation) error {
	time.Sleep(m.wait)
	return m.next.SubmitAttestations(ctx, attestations)
}

// ProposalSubmitter is a mock for eth2client.ProposalSubmitter.
type ProposalSubmitter struct{}

// NewProposalSubmitter returns a mock proposal submitter.
func NewProposalSubmitter() eth2client.ProposalSubmitter {
	return &ProposalSubmitter{}
}

// SubmitProposal is a mock.
func (*ProposalSubmitter) SubmitProposal(_ context.Context, _ *api.SubmitProposalOpts) error {
	return nil
}

// ErroringProposalSubmitter is a mock for eth2client.ProposalSubmitter that returns errors.
type ErroringProposalSubmitter struct{}

// NewErroringProposalSubmitter returns a mock beacon block submitter.
func NewErroringProposalSubmitter() eth2client.ProposalSubmitter {
	return &ErroringProposalSubmitter{}
}

// SubmitProposal is a mock.
func (*ErroringProposalSubmitter) SubmitProposal(_ context.Context, _ *api.SubmitProposalOpts) error {
	return errors.New("error")
}

// SleepyProposalSubmitter is a mock for eth2client.ProposalSubmitter.
type SleepyProposalSubmitter struct {
	wait time.Duration
	next eth2client.ProposalSubmitter
}

// NewSleepyProposalSubmitter returns a mock beacon block submitter.
func NewSleepyProposalSubmitter(wait time.Duration, next eth2client.ProposalSubmitter) eth2client.ProposalSubmitter {
	return &SleepyProposalSubmitter{
		wait: wait,
		next: next,
	}
}

// SubmitProposal is a mock.
func (m *SleepyProposalSubmitter) SubmitProposal(ctx context.Context, proposal *api.SubmitProposalOpts) error {
	time.Sleep(m.wait)
	return m.next.SubmitProposal(ctx, proposal)
}

// BlindedProposalSubmitter is a mock for eth2client.BlindedProposalSubmitter.
type BlindedProposalSubmitter struct{}

// NewBlindedProposalSubmitter returns a mock blinded proposal submitter.
func NewBlindedProposalSubmitter() eth2client.BlindedProposalSubmitter {
	return &BlindedProposalSubmitter{}
}

// SubmitBlindedProposal is a mock.
func (*BlindedProposalSubmitter) SubmitBlindedProposal(_ context.Context, _ *api.SubmitBlindedProposalOpts) error {
	return nil
}

// ErroringBlindedProposalSubmitter is a mock for eth2client.BlindedProposalSubmitter that returns errors.
type ErroringBlindedProposalSubmitter struct{}

// NewErroringBlindedProposalSubmitter returns a mock blinded proposal submitter.
func NewErroringBlindedProposalSubmitter() eth2client.BlindedProposalSubmitter {
	return &ErroringBlindedProposalSubmitter{}
}

// SubmitBlindedProposal is a mock.
func (*ErroringBlindedProposalSubmitter) SubmitBlindedProposal(_ context.Context, _ *api.SubmitBlindedProposalOpts) error {
	return errors.New("error")
}

// SleepyBlindedProposalSubmitter is a mock for eth2client.BlindedProposalSubmitter.
type SleepyBlindedProposalSubmitter struct {
	wait time.Duration
	next eth2client.BlindedProposalSubmitter
}

// NewSleepyBlindedProposalSubmitter returns a mock blinded proposal submitter.
func NewSleepyBlindedProposalSubmitter(wait time.Duration, next eth2client.BlindedProposalSubmitter) eth2client.BlindedProposalSubmitter {
	return &SleepyBlindedProposalSubmitter{
		wait: wait,
		next: next,
	}
}

// SubmitBlindedProposal is a mock.
func (m *SleepyBlindedProposalSubmitter) SubmitBlindedProposal(ctx context.Context, block *api.SubmitBlindedProposalOpts) error {
	time.Sleep(m.wait)
	return m.next.SubmitBlindedProposal(ctx, block)
}

// AggregateAttestationsSubmitter is a mock for eth2client.AggregateAttestationsSubmitter.
type AggregateAttestationsSubmitter struct{}

// NewAggregateAttestationsSubmitter returns a mock aggregate attestation submitter.
func NewAggregateAttestationsSubmitter() eth2client.AggregateAttestationsSubmitter {
	return &AggregateAttestationsSubmitter{}
}

// SubmitAggregateAttestations is a mock.
func (*AggregateAttestationsSubmitter) SubmitAggregateAttestations(_ context.Context, _ []*phase0.SignedAggregateAndProof) error {
	return nil
}

// ErroringAggregateAttestationsSubmitter is a mock for eth2client.AggregateAttestationsSubmitter that returns errors.
type ErroringAggregateAttestationsSubmitter struct{}

// NewErroringAggregateAttestationsSubmitter returns a mock aggregate attestation submitter.
func NewErroringAggregateAttestationsSubmitter() eth2client.AggregateAttestationsSubmitter {
	return &ErroringAggregateAttestationsSubmitter{}
}

// SubmitAggregateAttestations is a mock.
func (*ErroringAggregateAttestationsSubmitter) SubmitAggregateAttestations(_ context.Context, _ []*phase0.SignedAggregateAndProof) error {
	return errors.New("error")
}

// SleepyAggregateAttestationsSubmitter is a mock for eth2client.AggregateAttestationsSubmitter.
type SleepyAggregateAttestationsSubmitter struct {
	wait time.Duration
	next eth2client.AggregateAttestationsSubmitter
}

// NewSleepyAggregateAttestationsSubmitter returns a mock aggregate attestations submitter.
func NewSleepyAggregateAttestationsSubmitter(wait time.Duration, next eth2client.AggregateAttestationsSubmitter) eth2client.AggregateAttestationsSubmitter {
	return &SleepyAggregateAttestationsSubmitter{
		wait: wait,
		next: next,
	}
}

// SubmitAggregateAttestations is a mock.
func (m *SleepyAggregateAttestationsSubmitter) SubmitAggregateAttestations(ctx context.Context, aggregateAndProofs []*phase0.SignedAggregateAndProof) error {
	time.Sleep(m.wait)
	return m.next.SubmitAggregateAttestations(ctx, aggregateAndProofs)
}

// ProposalPreparationsSubmitter is a mock for eth2client.ProposalPreparationsSubmitter.
type ProposalPreparationsSubmitter struct{}

// NewProposalPreparationsSubmitter returns a mock proposal preparations submitter.
func NewProposalPreparationsSubmitter() eth2client.ProposalPreparationsSubmitter {
	return &ProposalPreparationsSubmitter{}
}

// SubmitProposalPreparations is a mock.
func (*ProposalPreparationsSubmitter) SubmitProposalPreparations(_ context.Context, _ []*apiv1.ProposalPreparation) error {
	return nil
}

// ErroringProposalPreparationsSubmitter is a mock for eth2client.ProposalPreparationsSubmitter that returns errors.
type ErroringProposalPreparationsSubmitter struct{}

// NewErroringProposalPreparationsSubmitter returns a mock aggregate attestation submitter.
func NewErroringProposalPreparationsSubmitter() eth2client.ProposalPreparationsSubmitter {
	return &ErroringProposalPreparationsSubmitter{}
}

// SubmitProposalPreparations is a mock.
func (*ErroringProposalPreparationsSubmitter) SubmitProposalPreparations(_ context.Context, _ []*apiv1.ProposalPreparation) error {
	return errors.New("error")
}

// SleepyProposalPreparationsSubmitter is a mock for eth2client.ProposalPreparationsSubmitter.
type SleepyProposalPreparationsSubmitter struct {
	wait time.Duration
	next eth2client.ProposalPreparationsSubmitter
}

// NewSleepyProposalPreparationsSubmitter returns a mock aggregate attestations submitter.
func NewSleepyProposalPreparationsSubmitter(wait time.Duration, next eth2client.ProposalPreparationsSubmitter) eth2client.ProposalPreparationsSubmitter {
	return &SleepyProposalPreparationsSubmitter{
		wait: wait,
		next: next,
	}
}

// SubmitProposalPreparations is a mock.
func (m *SleepyProposalPreparationsSubmitter) SubmitProposalPreparations(ctx context.Context, preparations []*apiv1.ProposalPreparation) error {
	time.Sleep(m.wait)
	return m.next.SubmitProposalPreparations(ctx, preparations)
}

// BeaconCommitteeSubscriptionsSubmitter is a mock for eth2client.BeaconCommitteeSubscriptionsSubmitter.
type BeaconCommitteeSubscriptionsSubmitter struct{}

// NewBeaconCommitteeSubscriptionsSubmitter returns a mock beacon committee subscriptions submitter.
func NewBeaconCommitteeSubscriptionsSubmitter() eth2client.BeaconCommitteeSubscriptionsSubmitter {
	return &BeaconCommitteeSubscriptionsSubmitter{}
}

// SubmitBeaconCommitteeSubscriptions is a mock.
func (*BeaconCommitteeSubscriptionsSubmitter) SubmitBeaconCommitteeSubscriptions(_ context.Context, _ []*apiv1.BeaconCommitteeSubscription) error {
	return nil
}

// ErroringBeaconCommitteeSubscriptionsSubmitter is a mock for eth2client.BeaconCommitteeSubscriptionsSubmitter that returns errors.
type ErroringBeaconCommitteeSubscriptionsSubmitter struct{}

// NewErroringBeaconCommitteeSubscriptionsSubmitter returns a mock beacon committee subscriptions submitter.
func NewErroringBeaconCommitteeSubscriptionsSubmitter() eth2client.BeaconCommitteeSubscriptionsSubmitter {
	return &ErroringBeaconCommitteeSubscriptionsSubmitter{}
}

// SubmitBeaconCommitteeSubscriptions is a mock.
func (*ErroringBeaconCommitteeSubscriptionsSubmitter) SubmitBeaconCommitteeSubscriptions(_ context.Context, _ []*apiv1.BeaconCommitteeSubscription) error {
	return errors.New("error")
}

// SleepyBeaconCommitteeSubscriptionsSubmitter is a mock for eth2client.BeaconCommitteeSubscriptionsSubmitter.
type SleepyBeaconCommitteeSubscriptionsSubmitter struct {
	wait time.Duration
	next eth2client.BeaconCommitteeSubscriptionsSubmitter
}

// NewSleepyBeaconCommitteeSubscriptionsSubmitter returns a mock beacon committee subscriptions submitter.
func NewSleepyBeaconCommitteeSubscriptionsSubmitter(wait time.Duration, next eth2client.BeaconCommitteeSubscriptionsSubmitter) eth2client.BeaconCommitteeSubscriptionsSubmitter {
	return &SleepyBeaconCommitteeSubscriptionsSubmitter{
		wait: wait,
		next: next,
	}
}

// SubmitBeaconCommitteeSubscriptions is a mock.
func (m *SleepyBeaconCommitteeSubscriptionsSubmitter) SubmitBeaconCommitteeSubscriptions(ctx context.Context, subscriptions []*apiv1.BeaconCommitteeSubscription) error {
	time.Sleep(m.wait)
	return m.next.SubmitBeaconCommitteeSubscriptions(ctx, subscriptions)
}

// ProposalProvider is a mock for eth2client.ProposalProvider.
type ProposalProvider struct{}

// NewProposalProvider returns a mock beacon block proposal provider.
func NewProposalProvider() eth2client.ProposalProvider {
	return &ProposalProvider{}
}

// Proposal is a mock.
func (*ProposalProvider) Proposal(_ context.Context,
	opts *api.ProposalOpts,
) (
	*api.Response[*api.VersionedProposal],
	error,
) {
	// Build a beacon block.

	// Create a few attestations.
	attestations := make([]*phase0.Attestation, 4)
	for i := range uint64(4) {
		aggregationBits := bitfield.NewBitlist(128)
		aggregationBits.SetBitAt(i, true)
		attestations[i] = &phase0.Attestation{
			AggregationBits: aggregationBits,
			Data: &phase0.AttestationData{
				Slot:  opts.Slot - 1,
				Index: phase0.CommitteeIndex(i),
				BeaconBlockRoot: phase0.Root([32]byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				}),
				Source: &phase0.Checkpoint{
					Epoch: 0,
					Root: phase0.Root([32]byte{
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					}),
				},
				Target: &phase0.Checkpoint{
					Epoch: 1,
					Root: phase0.Root([32]byte{
						0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
						0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
					}),
				},
			},
			Signature: phase0.BLSSignature([96]byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
				0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
				0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
			}),
		}
	}

	block := &api.VersionedProposal{
		Version:        spec.DataVersionCapella,
		ConsensusValue: big.NewInt(12345),
		ExecutionValue: big.NewInt(23456),
		Capella: &capella.BeaconBlock{
			Slot:          opts.Slot,
			ProposerIndex: 1,
			ParentRoot: phase0.Root([32]byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			}),
			StateRoot: phase0.Root([32]byte{
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
			}),
			Body: &capella.BeaconBlockBody{
				RANDAOReveal: opts.RandaoReveal,
				ETH1Data: &phase0.ETH1Data{
					DepositRoot: phase0.Root([32]byte{
						0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
						0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
					}),
					DepositCount: 16384,
					BlockHash: []byte{
						0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
						0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
					},
				},
				Graffiti:          opts.Graffiti,
				ProposerSlashings: []*phase0.ProposerSlashing{},
				AttesterSlashings: []*phase0.AttesterSlashing{},
				Attestations:      attestations,
				Deposits:          []*phase0.Deposit{},
				VoluntaryExits:    []*phase0.SignedVoluntaryExit{},
				ExecutionPayload: &capella.ExecutionPayload{
					FeeRecipient: bellatrix.ExecutionAddress{0x01},
				},
				SyncAggregate: &altair.SyncAggregate{},
			},
		},
	}

	return &api.Response[*api.VersionedProposal]{
		Data:     block,
		Metadata: make(map[string]any),
	}, nil
}

// ErroringProposalProvider is a mock for eth2client.ProposalProvider.
type ErroringProposalProvider struct{}

// NewErroringProposalProvider returns a mock beacon block proposal provider.
func NewErroringProposalProvider() eth2client.ProposalProvider {
	return &ErroringProposalProvider{}
}

// Proposal is a mock.
func (*ErroringProposalProvider) Proposal(_ context.Context,
	_ *api.ProposalOpts,
) (
	*api.Response[*api.VersionedProposal],
	error,
) {
	return nil, errors.New("error")
}

// SleepyProposalProvider is a mock for eth2client.ProposalProvider.
type SleepyProposalProvider struct {
	wait time.Duration
	next eth2client.ProposalProvider
}

// NewSleepyProposalProvider returns a mock beacon block proposal.
func NewSleepyProposalProvider(wait time.Duration, next eth2client.ProposalProvider) eth2client.ProposalProvider {
	return &SleepyProposalProvider{
		wait: wait,
		next: next,
	}
}

// Proposal is a mock.
func (m *SleepyProposalProvider) Proposal(ctx context.Context,
	opts *api.ProposalOpts,
) (
	*api.Response[*api.VersionedProposal],
	error,
) {
	time.Sleep(m.wait)
	return m.next.Proposal(ctx, opts)
}

// BeaconBlockRootProvider is a mock for eth2client.BeaconBlockRootProvider.
type BeaconBlockRootProvider struct{}

// NewBeaconBlockRootProvider returns a mock beacon block proposal provider.
func NewBeaconBlockRootProvider() eth2client.BeaconBlockRootProvider {
	return &BeaconBlockRootProvider{}
}

// BeaconBlockRoot is a mock.
func (*BeaconBlockRootProvider) BeaconBlockRoot(_ context.Context, _ *api.BeaconBlockRootOpts) (*api.Response[*phase0.Root], error) {
	root := phase0.Root([32]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	})

	return &api.Response[*phase0.Root]{
		Data:     &root,
		Metadata: make(map[string]any),
	}, nil
}

// ErroringBeaconBlockRootProvider is a mock for eth2client.BeaconBlockRootProvider.
type ErroringBeaconBlockRootProvider struct{}

// NewErroringBeaconBlockRootProvider returns a mock beacon block proposal provider.
func NewErroringBeaconBlockRootProvider() eth2client.BeaconBlockRootProvider {
	return &ErroringBeaconBlockRootProvider{}
}

// BeaconBlockRoot is a mock.
func (*ErroringBeaconBlockRootProvider) BeaconBlockRoot(_ context.Context, _ *api.BeaconBlockRootOpts) (*api.Response[*phase0.Root], error) {
	return nil, errors.New("error")
}

// SleepyBeaconBlockRootProvider is a mock for eth2client.BeaconBlockRootProvider.
type SleepyBeaconBlockRootProvider struct {
	wait time.Duration
	next eth2client.BeaconBlockRootProvider
}

// NewSleepyBeaconBlockRootProvider returns a mock beacon block root.
func NewSleepyBeaconBlockRootProvider(wait time.Duration, next eth2client.BeaconBlockRootProvider) eth2client.BeaconBlockRootProvider {
	return &SleepyBeaconBlockRootProvider{
		wait: wait,
		next: next,
	}
}

// BeaconBlockRoot is a mock.
func (m *SleepyBeaconBlockRootProvider) BeaconBlockRoot(ctx context.Context, opts *api.BeaconBlockRootOpts) (*api.Response[*phase0.Root], error) {
	time.Sleep(m.wait)
	return m.next.BeaconBlockRoot(ctx, opts)
}

// BeaconBlockHeadersProvider is a mock for eth2client.BeaconBlockHeadersProvider.
type BeaconBlockHeadersProvider struct{}

// NewBeaconBlockHeadersProvider returns a mock beacon block header provider.
func NewBeaconBlockHeadersProvider() eth2client.BeaconBlockHeadersProvider {
	return &BeaconBlockHeadersProvider{}
}

// BeaconBlockHeader provides the block header of a given block ID.
func (*BeaconBlockHeadersProvider) BeaconBlockHeader(_ context.Context,
	_ *api.BeaconBlockHeaderOpts,
) (
	*api.Response[*apiv1.BeaconBlockHeader],
	error,
) {
	return &api.Response[*apiv1.BeaconBlockHeader]{
		Data: &apiv1.BeaconBlockHeader{
			Root: phase0.Root([32]byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			}),
			Canonical: true,
			Header: &phase0.SignedBeaconBlockHeader{
				Message: &phase0.BeaconBlockHeader{
					Slot:          123,
					ProposerIndex: 234,
					ParentRoot: phase0.Root([32]byte{
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
					}),
					StateRoot: phase0.Root([32]byte{
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					}),
					BodyRoot: phase0.Root([32]byte{
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
						0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
					}),
				},
				Signature: phase0.BLSSignature([96]byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
					0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
					0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
					0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
				}),
			},
		},
		Metadata: make(map[string]any),
	}, nil
}

// ErroringBeaconBlockHeadersProvider is a mock for eth2client.BeaconBlockHeadersProvider.
type ErroringBeaconBlockHeadersProvider struct{}

// NewErroringBeaconBlockHeadersProvider returns a mock beacon block proposal provider.
func NewErroringBeaconBlockHeadersProvider() eth2client.BeaconBlockHeadersProvider {
	return &ErroringBeaconBlockHeadersProvider{}
}

// BeaconBlockHeader is a mock.
func (*ErroringBeaconBlockHeadersProvider) BeaconBlockHeader(_ context.Context, _ *api.BeaconBlockHeaderOpts) (*api.Response[*apiv1.BeaconBlockHeader], error) {
	return nil, errors.New("error")
}

// SleepyBeaconBlockHeadersProvider is a mock for eth2client.BeaconBlockHeadersProvider.
type SleepyBeaconBlockHeadersProvider struct {
	wait time.Duration
	next eth2client.BeaconBlockHeadersProvider
}

// NewSleepyBeaconBlockHeadersProvider returns a mock beacon block root.
func NewSleepyBeaconBlockHeadersProvider(wait time.Duration, next eth2client.BeaconBlockHeadersProvider) eth2client.BeaconBlockHeadersProvider {
	return &SleepyBeaconBlockHeadersProvider{
		wait: wait,
		next: next,
	}
}

// BeaconBlockHeader is a mock.
func (m *SleepyBeaconBlockHeadersProvider) BeaconBlockHeader(ctx context.Context, opts *api.BeaconBlockHeaderOpts) (*api.Response[*apiv1.BeaconBlockHeader], error) {
	time.Sleep(m.wait)
	return m.next.BeaconBlockHeader(ctx, opts)
}

// SignedBeaconBlockProvider is a mock for eth2client.SignedBeaconBlockProvider.
type SignedBeaconBlockProvider struct{}

// NewSignedBeaconBlockProvider returns a mock beacon block proposal provider.
func NewSignedBeaconBlockProvider() eth2client.SignedBeaconBlockProvider {
	return &SignedBeaconBlockProvider{}
}

// SignedBeaconBlock is a mock.
func (*SignedBeaconBlockProvider) SignedBeaconBlock(_ context.Context,
	_ *api.SignedBeaconBlockOpts,
) (
	*api.Response[*spec.VersionedSignedBeaconBlock],
	error,
) {
	return &api.Response[*spec.VersionedSignedBeaconBlock]{
		Data: &spec.VersionedSignedBeaconBlock{
			Version: spec.DataVersionPhase0,
			Phase0: &phase0.SignedBeaconBlock{
				Message: &phase0.BeaconBlock{
					Slot: 123,
				},
			},
		},
		Metadata: make(map[string]any),
	}, nil
}

// ErroringSignedBeaconBlockProvider is a mock for eth2client.SignedBeaconBlockProvider.
type ErroringSignedBeaconBlockProvider struct{}

// NewErroringSignedBeaconBlockProvider returns a mock signed beacon block provider.
func NewErroringSignedBeaconBlockProvider() eth2client.SignedBeaconBlockProvider {
	return &ErroringSignedBeaconBlockProvider{}
}

// SignedBeaconBlock is a mock.
func (*ErroringSignedBeaconBlockProvider) SignedBeaconBlock(_ context.Context, _ *api.SignedBeaconBlockOpts) (*api.Response[*spec.VersionedSignedBeaconBlock], error) {
	return nil, errors.New("error")
}

// SleepySignedBeaconBlockProvider is a mock for eth2client.SignedBeaconBlockProvider.
type SleepySignedBeaconBlockProvider struct {
	wait time.Duration
	next eth2client.SignedBeaconBlockProvider
}

// NewSleepySignedBeaconBlockProvider returns a mock beacon block root.
func NewSleepySignedBeaconBlockProvider(wait time.Duration, next eth2client.SignedBeaconBlockProvider) eth2client.SignedBeaconBlockProvider {
	return &SleepySignedBeaconBlockProvider{
		wait: wait,
		next: next,
	}
}

// SignedBeaconBlock is a mock.
func (m *SleepySignedBeaconBlockProvider) SignedBeaconBlock(ctx context.Context, opts *api.SignedBeaconBlockOpts) (*api.Response[*spec.VersionedSignedBeaconBlock], error) {
	time.Sleep(m.wait)
	return m.next.SignedBeaconBlock(ctx, opts)
}

// PrimedSignedBeaconBlockProvider is a mock for eth2client.SignedBeaconBlockProvider.
type PrimedSignedBeaconBlockProvider struct {
	response *api.Response[*spec.VersionedSignedBeaconBlock]
}

// NewPrimedSignedBeaconBlockProvider returns a mock beacon block proposal provider.
func NewPrimedSignedBeaconBlockProvider() *PrimedSignedBeaconBlockProvider {
	return &PrimedSignedBeaconBlockProvider{}
}

// SignedBeaconBlock is a mock.
func (p *PrimedSignedBeaconBlockProvider) SignedBeaconBlock(_ context.Context, _ *api.SignedBeaconBlockOpts) (*api.Response[*spec.VersionedSignedBeaconBlock], error) {
	return p.response, nil
}

// PrimeResponse is a mock.
func (p *PrimedSignedBeaconBlockProvider) PrimeResponse(response *api.Response[*spec.VersionedSignedBeaconBlock]) {
	p.response = response
}

// AttestationDataProvider is a mock for eth2client.AttestationDataProvider.
type AttestationDataProvider struct{}

// NewAttestationDataProvider returns a mock attestation data provider.
func NewAttestationDataProvider() eth2client.AttestationDataProvider {
	return &AttestationDataProvider{}
}

// AttestationData is a mock.
func (*AttestationDataProvider) AttestationData(_ context.Context,
	opts *api.AttestationDataOpts,
) (
	*api.Response[*phase0.AttestationData],
	error,
) {
	return &api.Response[*phase0.AttestationData]{
		Data: &phase0.AttestationData{
			Slot:  opts.Slot,
			Index: opts.CommitteeIndex,
			BeaconBlockRoot: phase0.Root([32]byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			}),
			Source: &phase0.Checkpoint{
				Epoch: phase0.Epoch(opts.Slot/32 - 1),
				Root: phase0.Root([32]byte{
					0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
					0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
				}),
			},
			Target: &phase0.Checkpoint{
				Epoch: phase0.Epoch(opts.Slot / 32),
				Root: phase0.Root([32]byte{
					0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
					0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
				}),
			},
		},
		Metadata: make(map[string]any),
	}, nil
}

// ErroringAttestationDataProvider is a mock for eth2client.AttestationDataProvider.
type ErroringAttestationDataProvider struct{}

// NewErroringAttestationDataProvider returns a mock attestation data provider.
func NewErroringAttestationDataProvider() eth2client.AttestationDataProvider {
	return &ErroringAttestationDataProvider{}
}

// AttestationData is a mock.
func (*ErroringAttestationDataProvider) AttestationData(_ context.Context,
	_ *api.AttestationDataOpts,
) (
	*api.Response[*phase0.AttestationData],
	error,
) {
	return nil, errors.New("mock error")
}

// SleepyAttestationDataProvider is a mock for eth2client.AttestationDataProvider.
type SleepyAttestationDataProvider struct {
	wait time.Duration
	next eth2client.AttestationDataProvider
}

// NewSleepyAttestationDataProvider returns a mock attestation data provider.
func NewSleepyAttestationDataProvider(wait time.Duration, next eth2client.AttestationDataProvider) eth2client.AttestationDataProvider {
	return &SleepyAttestationDataProvider{
		wait: wait,
		next: next,
	}
}

// AttestationData is a mock.
func (m *SleepyAttestationDataProvider) AttestationData(ctx context.Context,
	opts *api.AttestationDataOpts,
) (
	*api.Response[*phase0.AttestationData],
	error,
) {
	time.Sleep(m.wait)
	return m.next.AttestationData(ctx, opts)
}

// AggregateAttestationProvider is a mock for eth2client.AggregateAttestationProvider.
type AggregateAttestationProvider struct{}

// NewAggregateAttestationProvider returns a mock attestation data provider.
func NewAggregateAttestationProvider() eth2client.AggregateAttestationProvider {
	return &AggregateAttestationProvider{}
}

// AggregateAttestation is a mock.
func (*AggregateAttestationProvider) AggregateAttestation(_ context.Context,
	opts *api.AggregateAttestationOpts,
) (
	*api.Response[*phase0.Attestation],
	error,
) {
	aggregationBits := bitfield.NewBitlist(128)
	aggregationBits.SetBitAt(1, true)
	aggregationBits.SetBitAt(3, true)
	aggregationBits.SetBitAt(8, true)
	aggregationBits.SetBitAt(12, true)
	aggregationBits.SetBitAt(65, true)
	aggregationBits.SetBitAt(77, true)
	return &api.Response[*phase0.Attestation]{
		Data: &phase0.Attestation{
			AggregationBits: aggregationBits,
			Data: &phase0.AttestationData{
				Slot:  opts.Slot,
				Index: 1,
				BeaconBlockRoot: phase0.Root([32]byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				}),
				Source: &phase0.Checkpoint{
					Epoch: 1,
					Root: phase0.Root([32]byte{
						0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					}),
				},
				Target: &phase0.Checkpoint{
					Epoch: 2,
					Root: phase0.Root([32]byte{
						0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
						0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
					}),
				},
			},
			Signature: phase0.BLSSignature([96]byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
				0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
				0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
			}),
		},
		Metadata: make(map[string]any),
	}, nil
}

// ErroringAggregateAttestationProvider is a mock for eth2client.AggregateAttestationProvider.
type ErroringAggregateAttestationProvider struct{}

// NewErroringAggregateAttestationProvider returns a mock attestation data provider.
func NewErroringAggregateAttestationProvider() eth2client.AggregateAttestationProvider {
	return &ErroringAggregateAttestationProvider{}
}

// AggregateAttestation is a mock.
func (*ErroringAggregateAttestationProvider) AggregateAttestation(_ context.Context,
	_ *api.AggregateAttestationOpts,
) (
	*api.Response[*phase0.Attestation],
	error,
) {
	return nil, errors.New("mock error")
}

// SleepyAggregateAttestationProvider is a mock for eth2client.AggregateAttestationProvider.
type SleepyAggregateAttestationProvider struct {
	wait time.Duration
	next eth2client.AggregateAttestationProvider
}

// NewSleepyAggregateAttestationProvider returns a mock attestation data provider.
func NewSleepyAggregateAttestationProvider(wait time.Duration, next eth2client.AggregateAttestationProvider) eth2client.AggregateAttestationProvider {
	return &SleepyAggregateAttestationProvider{
		wait: wait,
		next: next,
	}
}

// AggregateAttestation is a mock.
func (m *SleepyAggregateAttestationProvider) AggregateAttestation(ctx context.Context,
	opts *api.AggregateAttestationOpts,
) (
	*api.Response[*phase0.Attestation],
	error,
) {
	time.Sleep(m.wait)
	return m.next.AggregateAttestation(ctx, opts)
}

// ErroringSpecProvider is a mock for eth2client.SpecProvider.
type ErroringSpecProvider struct{}

// NewErroringSpecProvider returns a mock spec provider.
func NewErroringSpecProvider() eth2client.SpecProvider {
	return &ErroringSpecProvider{}
}

// Spec is a mock.
func (*ErroringSpecProvider) Spec(_ context.Context, _ *api.SpecOpts) (*api.Response[map[string]any], error) {
	return nil, errors.New("error")
}

// SpecProvider is a mock for eth2client.SpecProvider.
type SpecProvider struct{}

// NewSpecProvider returns a mock spec provider.
func NewSpecProvider() eth2client.SpecProvider {
	return &SpecProvider{}
}

// Spec is a mock.
func (*SpecProvider) Spec(_ context.Context, _ *api.SpecOpts) (*api.Response[map[string]any], error) {
	return &api.Response[map[string]any]{
			Data: map[string]any{
				// Mainnet params (give or take).
				"DOMAIN_AGGREGATE_AND_PROOF":               phase0.DomainType{0x06, 0x00, 0x00, 0x00},
				"DOMAIN_BEACON_ATTESTER":                   phase0.DomainType{0x00, 0x00, 0x00, 0x00},
				"DOMAIN_BEACON_PROPOSER":                   phase0.DomainType{0x01, 0x00, 0x00, 0x00},
				"DOMAIN_CONTRIBUTION_AND_PROOF":            phase0.DomainType{0x09, 0x00, 0x00, 0x00},
				"DOMAIN_DEPOSIT":                           phase0.DomainType{0x03, 0x00, 0x00, 0x00},
				"DOMAIN_RANDAO":                            phase0.DomainType{0x02, 0x00, 0x00, 0x00},
				"DOMAIN_SELECTION_PROOF":                   phase0.DomainType{0x05, 0x00, 0x00, 0x00},
				"DOMAIN_SYNC_COMMITTEE":                    phase0.DomainType{0x07, 0x00, 0x00, 0x00},
				"DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF":    phase0.DomainType{0x08, 0x00, 0x00, 0x00},
				"DOMAIN_VOLUNTARY_EXIT":                    phase0.DomainType{0x04, 0x00, 0x00, 0x00},
				"DOMAIN_APPLICATION_BUILDER":               phase0.DomainType{0x00, 0x00, 0x00, 0x01},
				"EPOCHS_PER_SYNC_COMMITTEE_PERIOD":         uint64(256),
				"SECONDS_PER_SLOT":                         12 * time.Second,
				"SLOTS_PER_EPOCH":                          uint64(32),
				"SYNC_COMMITTEE_SIZE":                      uint64(512),
				"SYNC_COMMITTEE_SUBNET_COUNT":              uint64(4),
				"TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE": uint64(16),
			},
			Metadata: make(map[string]any),
		},
		nil
}

// ForkScheduleProvider is a mock for eth2client.ForkScheduleProvider.
type ForkScheduleProvider struct{}

// NewForkScheduleProvider returns a mock fork schedule provider.
func NewForkScheduleProvider() eth2client.ForkScheduleProvider {
	return &ForkScheduleProvider{}
}

// ForkSchedule is a mock.
func (*ForkScheduleProvider) ForkSchedule(_ context.Context, _ *api.ForkScheduleOpts) (*api.Response[[]*phase0.Fork], error) {
	return &api.Response[[]*phase0.Fork]{
		Data: []*phase0.Fork{
			{
				PreviousVersion: phase0.Version{0x00, 0x01, 0x02, 0x03},
				CurrentVersion:  phase0.Version{0x00, 0x01, 0x02, 0x03},
				Epoch:           0,
			},
			{
				PreviousVersion: phase0.Version{0x00, 0x01, 0x02, 0x03},
				CurrentVersion:  phase0.Version{0x01, 0x02, 0x03, 0x04},
				Epoch:           10,
			},
		},
		Metadata: make(map[string]any),
	}, nil
}

// DomainProvider is a mock for eth2client.DomainProvider.
type DomainProvider struct{}

// NewDomainProvider returns a mock domain provider.
func NewDomainProvider() eth2client.DomainProvider {
	return &DomainProvider{}
}

// Domain is a mock.
func (*DomainProvider) Domain(_ context.Context, domainType phase0.DomainType, _ phase0.Epoch) (phase0.Domain, error) {
	var domain phase0.Domain
	// Put the domain type in the first four bytes, to differentiate signatures.
	copy(domain[:], domainType[:])

	return domain, nil
}

// GenesisDomain is a mock.
func (*DomainProvider) GenesisDomain(_ context.Context, domainType phase0.DomainType) (phase0.Domain, error) {
	var domain phase0.Domain
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
func (*ErroringDomainProvider) Domain(_ context.Context, _ phase0.DomainType, _ phase0.Epoch) (phase0.Domain, error) {
	return phase0.Domain{}, errors.New("error")
}

// GenesisDomain is a mock.
func (*ErroringDomainProvider) GenesisDomain(_ context.Context, _ phase0.DomainType) (phase0.Domain, error) {
	return phase0.Domain{}, errors.New("error")
}

func _byte(input string) []byte {
	res, _ := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	return res
}

func _blsPubKey(input string) phase0.BLSPubKey {
	tmp, _ := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	var res phase0.BLSPubKey
	copy(res[:], tmp)
	return res
}

func _epochValidator(index phase0.ValidatorIndex, pubKey string, withdrwalCredentials string) *apiv1.Validator {
	return &apiv1.Validator{
		Index:   index,
		Balance: 32000000000,
		Status:  apiv1.ValidatorStateActiveOngoing,
		Validator: &phase0.Validator{
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

// ValidatorsProvider is a mock.
type ValidatorsProvider struct{}

// NewValidatorsProvider returns a mock validators provider.
func NewValidatorsProvider() eth2client.ValidatorsProvider {
	return &ValidatorsProvider{}
}

// Validators is a mock.
func (*ValidatorsProvider) Validators(ctx context.Context,
	opts *api.ValidatorsOpts,
) (
	*api.Response[map[phase0.ValidatorIndex]*apiv1.Validator],
	error,
) {
	base := map[phase0.ValidatorIndex]*apiv1.Validator{
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

	var res map[phase0.ValidatorIndex]*apiv1.Validator
	switch {
	case len(opts.Indices) == 0 && len(opts.PubKeys) == 0:
		res = base
	case len(opts.Indices) > 0:
		res = make(map[phase0.ValidatorIndex]*apiv1.Validator)
		for k, v := range base {
			for _, index := range opts.Indices {
				if k == index {
					res[k] = v
					break
				}
			}
		}
	case len(opts.PubKeys) > 0:
		res = make(map[phase0.ValidatorIndex]*apiv1.Validator)
		for k, v := range base {
			for _, pubKey := range opts.PubKeys {
				p, _ := v.PubKey(ctx)
				if bytes.Equal(p[:], pubKey[:]) {
					res[k] = v
					break
				}
			}
		}
	}
	return &api.Response[map[phase0.ValidatorIndex]*apiv1.Validator]{
		Data:     res,
		Metadata: make(map[string]any),
	}, nil
}

// ValidatorsByPubKey is a mock.
func (*ValidatorsProvider) ValidatorsByPubKey(_ context.Context, _ string, validators []phase0.BLSPubKey) (map[phase0.ValidatorIndex]*apiv1.Validator, error) {
	base := map[phase0.ValidatorIndex]*apiv1.Validator{
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

	if len(validators) == 0 {
		return base, nil
	}

	res := make(map[phase0.ValidatorIndex]*apiv1.Validator)
	for k, v := range base {
		for _, pubKey := range validators {
			if v.Validator.PublicKey == pubKey {
				res[k] = v
				break
			}
		}
	}
	return res, nil
}

// SyncCommitteeContributionProvider is a mock for eth2client.SyncCommitteeContributionProvider.
type SyncCommitteeContributionProvider struct{}

// NewSyncCommitteeContributionProvider returns a mock attestation data provider.
func NewSyncCommitteeContributionProvider() eth2client.SyncCommitteeContributionProvider {
	return &SyncCommitteeContributionProvider{}
}

// SyncCommitteeContribution is a mock.
func (*SyncCommitteeContributionProvider) SyncCommitteeContribution(_ context.Context,
	opts *api.SyncCommitteeContributionOpts,
) (
	*api.Response[*altair.SyncCommitteeContribution],
	error,
) {
	aggregationBits := bitfield.NewBitvector128()
	aggregationBits.SetBitAt(1, true)
	aggregationBits.SetBitAt(3, true)
	aggregationBits.SetBitAt(8, true)
	aggregationBits.SetBitAt(12, true)
	aggregationBits.SetBitAt(65, true)
	aggregationBits.SetBitAt(77, true)
	return &api.Response[*altair.SyncCommitteeContribution]{
		Data: &altair.SyncCommitteeContribution{
			Slot:              opts.Slot,
			BeaconBlockRoot:   opts.BeaconBlockRoot,
			SubcommitteeIndex: opts.SubcommitteeIndex,
			AggregationBits:   aggregationBits,
			Signature: phase0.BLSSignature([96]byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
				0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
				0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
			}),
		},
		Metadata: make(map[string]any),
	}, nil
}

// ErroringSyncCommitteeContributionProvider is a mock for eth2client.SyncCommitteeContributionProvider.
type ErroringSyncCommitteeContributionProvider struct{}

// NewErroringSyncCommitteeContributionProvider returns a mock attestation data provider.
func NewErroringSyncCommitteeContributionProvider() eth2client.SyncCommitteeContributionProvider {
	return &ErroringSyncCommitteeContributionProvider{}
}

// SyncCommitteeContribution is a mock.
func (*ErroringSyncCommitteeContributionProvider) SyncCommitteeContribution(_ context.Context,
	_ *api.SyncCommitteeContributionOpts,
) (
	*api.Response[*altair.SyncCommitteeContribution],
	error,
) {
	return nil, errors.New("mock error")
}

// SleepySyncCommitteeContributionProvider is a mock for eth2client.SyncCommitteeContributionProvider.
type SleepySyncCommitteeContributionProvider struct {
	wait time.Duration
	next eth2client.SyncCommitteeContributionProvider
}

// NewSleepySyncCommitteeContributionProvider returns a mock attestation data provider.
func NewSleepySyncCommitteeContributionProvider(wait time.Duration, next eth2client.SyncCommitteeContributionProvider) eth2client.SyncCommitteeContributionProvider {
	return &SleepySyncCommitteeContributionProvider{
		wait: wait,
		next: next,
	}
}

// SyncCommitteeContribution is a mock.
func (m *SleepySyncCommitteeContributionProvider) SyncCommitteeContribution(ctx context.Context,
	opts *api.SyncCommitteeContributionOpts,
) (
	*api.Response[*altair.SyncCommitteeContribution],
	error,
) {
	time.Sleep(m.wait)
	return m.next.SyncCommitteeContribution(ctx, opts)
}
