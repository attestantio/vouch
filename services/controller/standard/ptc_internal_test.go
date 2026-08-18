// Copyright © 2026 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");

package standard

import (
	"context"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/payloadattester"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/stretchr/testify/require"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestSchedulePayloadAttestationsGroupsDutiesAndCallsService(t *testing.T) {
	ctx := context.Background()
	provider := &recordingPTCDutiesProvider{
		duties: []*apiv1.PTCDuty{
			{Slot: 10, ValidatorIndex: 1},
			{Slot: 10, ValidatorIndex: 2},
			{Slot: 11, ValidatorIndex: 3},
		},
	}
	accounts := &recordingAccountsProvider{}
	schedulerService := &recordingScheduler{}
	payloadService := &recordingPayloadAttester{}
	chainTime := &recordingChainTime{slotDuration: time.Second, slotsPerEpoch: 32}

	service := &Service{
		chainTimeService:           chainTime,
		ptcDutiesProvider:          provider,
		validatingAccountsProvider: accounts,
		scheduler:                  schedulerService,
		payloadAttester:            payloadService,
		payloadDueDelay:            500 * time.Millisecond,
		payloadAttestationDelay:    750 * time.Millisecond,
		gloasForkEpoch:             0,
	}

	service.schedulePayloadAttestations(ctx, 0, []phase0.ValidatorIndex{1, 2, 3}, false)

	require.Equal(t, 1, provider.calls)
	require.Equal(t, []phase0.ValidatorIndex{1, 2, 3}, accounts.indices)
	require.Len(t, schedulerService.jobs, 2)

	job := schedulerService.jobs[0]
	require.Equal(t, chainTime.StartOfSlot(10).Add(500*time.Millisecond), job.runtime)
	job.job(ctx)

	require.Len(t, payloadService.duties, 1)
	require.Equal(t, chainTime.StartOfSlot(10).Add(750*time.Millisecond), payloadService.deadline)
	require.Equal(t, phase0.Slot(10), payloadService.duties[0].Slot())
	require.Equal(t, []phase0.ValidatorIndex{1, 2}, payloadService.duties[0].ValidatorIndices())
	require.Len(t, payloadService.duties[0].Accounts(), 2)
}

func TestSchedulePayloadAttestationsIsInactiveBeforeGloas(t *testing.T) {
	service := &Service{
		chainTimeService:  &recordingChainTime{currentEpoch: 4, slotsPerEpoch: 32},
		ptcDutiesProvider: &recordingPTCDutiesProvider{},
		scheduler:         &recordingScheduler{},
		payloadAttester:   &recordingPayloadAttester{},
		gloasForkEpoch:    5,
	}

	service.schedulePayloadAttestations(context.Background(), 4, []phase0.ValidatorIndex{1}, false)

	require.Equal(t, 0, service.ptcDutiesProvider.(*recordingPTCDutiesProvider).calls)
	require.Empty(t, service.scheduler.(*recordingScheduler).jobs)
}

func TestRefreshPayloadAttestationsReschedulesAfterDependentRootChange(t *testing.T) {
	schedulerService := &recordingScheduler{}
	service := &Service{
		chainTimeService:           &recordingChainTime{currentEpoch: 0, slotsPerEpoch: 32},
		ptcDutiesProvider:          &recordingPTCDutiesProvider{duties: []*apiv1.PTCDuty{{Slot: 10, ValidatorIndex: 1}}},
		validatingAccountsProvider: &recordingAccountsProvider{epochIndices: []phase0.ValidatorIndex{1}},
		scheduler:                  schedulerService,
		payloadAttester:            &recordingPayloadAttester{},
		payloadAttestationDelay:    time.Second,
		gloasForkEpoch:             0,
	}

	service.refreshPayloadAttestationDutiesForEpoch(context.Background(), 0)

	require.Contains(t, schedulerService.cancelled, "Payload attestations for slot 10")
	require.Len(t, schedulerService.jobs, 1)
}

func TestSchedulePayloadAttestationsDoesNotRefetchScheduledEpoch(t *testing.T) {
	provider := &recordingPTCDutiesProvider{duties: []*apiv1.PTCDuty{{Slot: 42, ValidatorIndex: 1}}}
	schedulerService := &recordingScheduler{existing: map[string]bool{"Payload attestations for slot 42": true}}
	service := &Service{
		chainTimeService:           &recordingChainTime{slotsPerEpoch: 32},
		ptcDutiesProvider:          provider,
		validatingAccountsProvider: &recordingAccountsProvider{},
		scheduler:                  schedulerService,
		payloadAttester:            &recordingPayloadAttester{},
		payloadDueDelay:            500 * time.Millisecond,
		payloadAttestationDelay:    750 * time.Millisecond,
		gloasForkEpoch:             0,
	}

	service.schedulePayloadAttestations(context.Background(), 1, []phase0.ValidatorIndex{1}, false)

	require.Equal(t, 0, provider.calls)
	require.Empty(t, schedulerService.jobs)
}

func TestSchedulePayloadAttestationsSkipsPastAndCurrentSlotWhenRequested(t *testing.T) {
	provider := &recordingPTCDutiesProvider{duties: []*apiv1.PTCDuty{
		{Slot: 31, ValidatorIndex: 1},
		{Slot: 32, ValidatorIndex: 2},
		{Slot: 33, ValidatorIndex: 3},
	}}
	schedulerService := &recordingScheduler{}
	service := &Service{
		chainTimeService:           &recordingChainTime{currentEpoch: 1, slotsPerEpoch: 32},
		ptcDutiesProvider:          provider,
		validatingAccountsProvider: &recordingAccountsProvider{},
		scheduler:                  schedulerService,
		payloadAttester:            &recordingPayloadAttester{},
		gloasForkEpoch:             0,
	}

	service.schedulePayloadAttestations(context.Background(), 1, []phase0.ValidatorIndex{1, 2, 3}, true)

	require.Len(t, schedulerService.jobs, 1)
	schedulerService.jobs[0].job(context.Background())
	require.Len(t, service.payloadAttester.(*recordingPayloadAttester).duties, 1)
	require.Equal(t, phase0.Slot(33), service.payloadAttester.(*recordingPayloadAttester).duties[0].Slot())
}

type recordingPTCDutiesProvider struct {
	duties []*apiv1.PTCDuty
	calls  int
}

func (p *recordingPTCDutiesProvider) PTCDuties(_ context.Context, _ *api.PTCDutiesOpts) (*api.Response[[]*apiv1.PTCDuty], error) {
	p.calls++
	return &api.Response[[]*apiv1.PTCDuty]{Data: p.duties}, nil
}

type recordingAccountsProvider struct {
	indices      []phase0.ValidatorIndex
	epochIndices []phase0.ValidatorIndex
}

func (p *recordingAccountsProvider) ValidatingAccountsForEpoch(_ context.Context, _ phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	accounts := make(map[phase0.ValidatorIndex]e2wtypes.Account, len(p.epochIndices))
	for _, index := range p.epochIndices {
		accounts[index] = nil
	}
	return accounts, nil
}

func (p *recordingAccountsProvider) ValidatingAccountsForEpochByIndex(_ context.Context, _ phase0.Epoch, indices []phase0.ValidatorIndex) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	p.indices = append([]phase0.ValidatorIndex(nil), indices...)
	accounts := make(map[phase0.ValidatorIndex]e2wtypes.Account, len(indices))
	for _, index := range indices {
		accounts[index] = nil
	}
	return accounts, nil
}

func (*recordingAccountsProvider) SyncCommitteeAccountsForEpoch(_ context.Context, _ phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return nil, nil
}

func (*recordingAccountsProvider) SyncCommitteeAccountsForEpochByIndex(_ context.Context, _ phase0.Epoch, _ []phase0.ValidatorIndex) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return nil, nil
}

type recordingScheduler struct {
	jobs      []recordedJob
	cancelled []string
	existing  map[string]bool
}

type recordedJob struct {
	runtime time.Time
	job     scheduler.JobFunc
}

func (s *recordingScheduler) ScheduleJob(_ context.Context, _ string, _ string, runtime time.Time, job scheduler.JobFunc) error {
	s.jobs = append(s.jobs, recordedJob{runtime: runtime, job: job})
	return nil
}

func (*recordingScheduler) SchedulePeriodicJob(context.Context, string, string, scheduler.RuntimeFunc, scheduler.JobFunc) error {
	return nil
}

func (s *recordingScheduler) CancelJob(_ context.Context, name string) error {
	s.cancelled = append(s.cancelled, name)
	return nil
}
func (s *recordingScheduler) CancelJobIfExists(_ context.Context, name string) {
	s.cancelled = append(s.cancelled, name)
}
func (*recordingScheduler) CancelJobs(context.Context, string)              {}
func (*recordingScheduler) RunJob(context.Context, string) error            { return nil }
func (s *recordingScheduler) JobExists(_ context.Context, name string) bool { return s.existing[name] }
func (*recordingScheduler) RunJobIfExists(context.Context, string)          {}
func (*recordingScheduler) ListJobs(context.Context) []string               { return nil }

type recordingPayloadAttester struct {
	duties   []*payloadattester.Duty
	deadline time.Time
}

func (*recordingPayloadAttester) Prepare(context.Context, *payloadattester.Duty) error { return nil }

func (s *recordingPayloadAttester) Attest(ctx context.Context, duty *payloadattester.Duty) ([]*spec.VersionedPayloadAttestationMessage, error) {
	s.deadline, _ = ctx.Deadline()
	s.duties = append(s.duties, duty)
	return nil, nil
}

type recordingChainTime struct {
	currentEpoch  phase0.Epoch
	slotDuration  time.Duration
	slotsPerEpoch uint64
}

func (*recordingChainTime) GenesisTime() time.Time { return time.Unix(0, 0) }
func (s *recordingChainTime) StartOfSlot(slot phase0.Slot) time.Time {
	return time.Unix(0, 0).Add(time.Duration(slot) * s.slotDuration)
}
func (s *recordingChainTime) StartOfEpoch(epoch phase0.Epoch) time.Time {
	return s.StartOfSlot(phase0.Slot(uint64(epoch) * s.slotsPerEpoch))
}
func (s *recordingChainTime) CurrentSlot() phase0.Slot {
	return phase0.Slot(uint64(s.currentEpoch) * s.slotsPerEpoch)
}
func (s *recordingChainTime) CurrentEpoch() phase0.Epoch { return s.currentEpoch }
func (s *recordingChainTime) SlotToEpoch(slot phase0.Slot) phase0.Epoch {
	return phase0.Epoch(uint64(slot) / s.slotsPerEpoch)
}
func (s *recordingChainTime) FirstSlotOfEpoch(epoch phase0.Epoch) phase0.Slot {
	return phase0.Slot(uint64(epoch) * s.slotsPerEpoch)
}
func (*recordingChainTime) HardForkEpoch(context.Context, string) phase0.Epoch { return 0 }
