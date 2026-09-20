// Copyright © 2026 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");

package standard

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/payloadattester"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/stretchr/testify/require"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestExecutionPayloadAvailableRetainsDeadlineAfterDataUnavailable(t *testing.T) {
	ctx := context.Background()
	schedulerService := &recordingScheduler{}
	payloadService := &recordingPayloadAttester{err: eth2client.ErrNoPayloadAttestationData}
	service := &Service{
		chainTimeService:        currentSlotRecordingChainTime(10),
		scheduler:               schedulerService,
		payloadAttester:         payloadService,
		payloadAttestationDelay: 9 * time.Second,
	}
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 10, ValidatorIndex: 1})

	service.schedulePayloadAttestation(ctx, duty, map[phase0.ValidatorIndex]e2wtypes.Account{1: nil})
	service.HandleExecutionPayloadAvailableEvent(ctx, &apiv1.ExecutionPayloadAvailableEvent{Slot: 10})

	require.Len(t, payloadService.duties, 1)
	require.True(t, schedulerService.JobExists(ctx, payloadAttestationJobName(10)))
}

func TestPayloadAttestationDeadlineRetriesAfterEventDataUnavailable(t *testing.T) {
	ctx := context.Background()
	schedulerService := &recordingScheduler{}
	payloadService := &recordingPayloadAttester{err: eth2client.ErrNoPayloadAttestationData}
	service := &Service{
		chainTimeService:        currentSlotRecordingChainTime(10),
		scheduler:               schedulerService,
		payloadAttester:         payloadService,
		payloadAttestationDelay: 9 * time.Second,
	}
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 10, ValidatorIndex: 1})

	service.schedulePayloadAttestation(ctx, duty, map[phase0.ValidatorIndex]e2wtypes.Account{1: nil})
	service.HandleExecutionPayloadAvailableEvent(ctx, &apiv1.ExecutionPayloadAvailableEvent{Slot: 10})
	payloadService.err = nil
	schedulerService.RunJobIfExists(ctx, payloadAttestationJobName(10))

	require.Len(t, payloadService.duties, 2)
}

func TestExecutionPayloadAvailableDoesNotRetryNonDataErrorAtDeadline(t *testing.T) {
	ctx := context.Background()
	schedulerService := &recordingScheduler{}
	payloadService := &recordingPayloadAttester{err: errors.New("signing failed")}
	service := &Service{
		chainTimeService:        currentSlotRecordingChainTime(10),
		scheduler:               schedulerService,
		payloadAttester:         payloadService,
		payloadAttestationDelay: 9 * time.Second,
	}
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 10, ValidatorIndex: 1})

	service.schedulePayloadAttestation(ctx, duty, map[phase0.ValidatorIndex]e2wtypes.Account{1: nil})
	service.HandleExecutionPayloadAvailableEvent(ctx, &apiv1.ExecutionPayloadAvailableEvent{Slot: 10})
	schedulerService.RunJobIfExists(ctx, payloadAttestationJobName(10))

	require.Len(t, payloadService.duties, 1)
}

func TestExecutionPayloadAvailableRunsScheduledPayloadAttestation(t *testing.T) {
	ctx := context.Background()
	schedulerService := &recordingScheduler{}
	payloadService := &recordingPayloadAttester{}
	service := &Service{
		chainTimeService:        currentSlotRecordingChainTime(10),
		scheduler:               schedulerService,
		payloadAttester:         payloadService,
		payloadAttestationDelay: 9 * time.Second,
	}
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 10, ValidatorIndex: 1})

	service.schedulePayloadAttestation(ctx, duty, map[phase0.ValidatorIndex]e2wtypes.Account{1: nil})
	service.HandleExecutionPayloadAvailableEvent(ctx, &apiv1.ExecutionPayloadAvailableEvent{Slot: 10})

	require.Len(t, payloadService.duties, 1)
	require.False(t, schedulerService.JobExists(ctx, payloadAttestationJobName(10)))
}

func TestExecutionPayloadAvailableAttemptRunsToEndOfSlot(t *testing.T) {
	ctx := context.Background()
	chainTime := currentSlotRecordingChainTime(10)
	payloadService := &recordingPayloadAttester{}
	service := &Service{
		chainTimeService:        chainTime,
		scheduler:               &recordingScheduler{},
		payloadAttester:         payloadService,
		payloadAttestationDelay: 9 * time.Second,
	}
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 10, ValidatorIndex: 1})

	service.schedulePayloadAttestation(ctx, duty, map[phase0.ValidatorIndex]e2wtypes.Account{1: nil})
	service.HandleExecutionPayloadAvailableEvent(ctx, &apiv1.ExecutionPayloadAvailableEvent{Slot: 10})

	require.Equal(t, chainTime.StartOfSlot(11), payloadService.deadline)
}

func TestDuplicateExecutionPayloadAvailableDoesNotRerunPayloadAttestation(t *testing.T) {
	ctx := context.Background()
	schedulerService := &recordingScheduler{}
	payloadService := &recordingPayloadAttester{}
	service := &Service{
		chainTimeService:        currentSlotRecordingChainTime(10),
		scheduler:               schedulerService,
		payloadAttester:         payloadService,
		payloadAttestationDelay: 9 * time.Second,
	}
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 10, ValidatorIndex: 1})
	event := &apiv1.ExecutionPayloadAvailableEvent{Slot: 10}

	service.schedulePayloadAttestation(ctx, duty, map[phase0.ValidatorIndex]e2wtypes.Account{1: nil})
	service.HandleExecutionPayloadAvailableEvent(ctx, event)
	service.HandleExecutionPayloadAvailableEvent(ctx, event)

	require.Len(t, payloadService.duties, 1)
}

func TestLateExecutionPayloadAvailableDoesNothing(t *testing.T) {
	payloadService := &recordingPayloadAttester{}
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 10, ValidatorIndex: 1})
	service := &Service{
		chainTimeService: &recordingChainTime{slotDuration: 12 * time.Second, slotsPerEpoch: 32},
		scheduler:        &recordingScheduler{},
		payloadAttester:  payloadService,
		payloadAttestations: map[phase0.Slot]*payloadAttestation{
			10: {duty: duty, deadline: time.Now().Add(-time.Second)},
		},
	}

	service.HandleExecutionPayloadAvailableEvent(context.Background(), &apiv1.ExecutionPayloadAvailableEvent{Slot: 10})

	require.Empty(t, payloadService.duties)
}

func TestExecutionPayloadAvailableWithoutDutyDoesNothing(t *testing.T) {
	ctx := context.Background()
	schedulerService := &recordingScheduler{existing: make(map[string]bool)}
	service := &Service{scheduler: schedulerService}

	service.HandleExecutionPayloadAvailableEvent(ctx, &apiv1.ExecutionPayloadAvailableEvent{Slot: 10})

	require.Empty(t, schedulerService.cancelled)
}

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
		payloadAttestationDelay:    750 * time.Millisecond,
		gloasForkEpoch:             0,
	}

	service.schedulePayloadAttestations(ctx, 0, []phase0.ValidatorIndex{1, 2, 3}, false)

	require.Equal(t, 1, provider.calls)
	require.Equal(t, []phase0.ValidatorIndex{1, 2, 3}, accounts.indices)
	require.Len(t, schedulerService.jobs, 2)
	require.Len(t, payloadService.prepared, 2)

	job := schedulerService.jobs[0]
	job.job(ctx)

	require.Len(t, payloadService.duties, 1)
	require.Equal(t, phase0.Slot(10), payloadService.duties[0].Slot())
	require.Equal(t, []phase0.ValidatorIndex{1, 2}, payloadService.duties[0].ValidatorIndices())
	require.Len(t, payloadService.duties[0].Accounts(), 2)
}

func TestSchedulePayloadAttestationDoesNotPrepareWhenSchedulingFails(t *testing.T) {
	ctx := context.Background()
	schedulerService := &recordingScheduler{err: errors.New("scheduler failed")}
	payloadService := &recordingPayloadAttester{}
	service := &Service{
		chainTimeService:        &recordingChainTime{slotDuration: time.Second, slotsPerEpoch: 32},
		scheduler:               schedulerService,
		payloadAttester:         payloadService,
		payloadAttestationDelay: time.Second,
	}
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 10, ValidatorIndex: 1})

	service.schedulePayloadAttestation(ctx, duty, map[phase0.ValidatorIndex]e2wtypes.Account{})

	require.Empty(t, payloadService.prepared)
}

// TestSchedulePayloadAttestationVotesAtTheAttestationDeadline confirms that the vote is cast at the
// payload attestation deadline rather than when the payload becomes due.  payload_present is a
// question about the payload due time that only the beacon node can answer, and a beacon node does
// not serve an answer it does not yet consider final, so voting at the payload due time returns no
// data at all for exactly the marginal payloads the vote exists to judge.
func TestSchedulePayloadAttestationVotesAtTheAttestationDeadline(t *testing.T) {
	ctx := context.Background()
	schedulerService := &recordingScheduler{}
	chainTime := &recordingChainTime{slotDuration: 12 * time.Second, slotsPerEpoch: 32}
	service := &Service{
		chainTimeService:           chainTime,
		ptcDutiesProvider:          &recordingPTCDutiesProvider{duties: []*apiv1.PTCDuty{{Slot: 10, ValidatorIndex: 1}}},
		validatingAccountsProvider: &recordingAccountsProvider{},
		scheduler:                  schedulerService,
		payloadAttester:            &recordingPayloadAttester{},
		payloadAttestationDelay:    9 * time.Second,
		gloasForkEpoch:             0,
	}

	service.schedulePayloadAttestations(ctx, 0, []phase0.ValidatorIndex{1}, false)

	require.Len(t, schedulerService.jobs, 1)
	require.Equal(t, chainTime.StartOfSlot(10).Add(9*time.Second), schedulerService.jobs[0].runtime)
}

// TestSchedulePayloadAttestationDeadlineRunsToTheEndOfTheSlot confirms that the vote's context runs
// to the end of its slot rather than to the payload attestation deadline.  The vote is cast at that
// deadline, so a context expiring on it would cut off the signing and submission it is there to
// bound, and the gossip rule accepts a payload attestation for the whole of its slot.
func TestSchedulePayloadAttestationDeadlineRunsToTheEndOfTheSlot(t *testing.T) {
	ctx := context.Background()
	schedulerService := &recordingScheduler{}
	payloadService := &recordingPayloadAttester{}
	chainTime := &recordingChainTime{slotDuration: 12 * time.Second, slotsPerEpoch: 32}
	service := &Service{
		chainTimeService:           chainTime,
		ptcDutiesProvider:          &recordingPTCDutiesProvider{duties: []*apiv1.PTCDuty{{Slot: 10, ValidatorIndex: 1}}},
		validatingAccountsProvider: &recordingAccountsProvider{},
		scheduler:                  schedulerService,
		payloadAttester:            payloadService,
		payloadAttestationDelay:    9 * time.Second,
		gloasForkEpoch:             0,
	}

	service.schedulePayloadAttestations(ctx, 0, []phase0.ValidatorIndex{1}, false)

	require.Len(t, schedulerService.jobs, 1)
	schedulerService.jobs[0].job(ctx)

	require.Equal(t, chainTime.StartOfSlot(11), payloadService.deadline)
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

func TestRefreshPayloadAttestationsDoesNotReplaceInFlightSuccessfulAttempt(t *testing.T) {
	ctx := context.Background()
	schedulerService := &recordingScheduler{}
	payloadService := &blockingPayloadAttester{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	service := &Service{
		chainTimeService:           currentSlotRecordingChainTime(0),
		ptcDutiesProvider:          &recordingPTCDutiesProvider{duties: []*apiv1.PTCDuty{{Slot: 0, ValidatorIndex: 1}}},
		validatingAccountsProvider: &recordingAccountsProvider{epochIndices: []phase0.ValidatorIndex{1}},
		scheduler:                  schedulerService,
		payloadAttester:            payloadService,
		payloadAttestationDelay:    9 * time.Second,
		gloasForkEpoch:             0,
	}
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 0, ValidatorIndex: 1})
	service.schedulePayloadAttestation(ctx, duty, map[phase0.ValidatorIndex]e2wtypes.Account{1: nil})

	eventDone := make(chan struct{})
	go func() {
		service.HandleExecutionPayloadAvailableEvent(ctx, &apiv1.ExecutionPayloadAvailableEvent{Slot: 0})
		close(eventDone)
	}()
	<-payloadService.started
	refreshDone := make(chan struct{})
	go func() {
		service.refreshPayloadAttestationDutiesForEpoch(ctx, 0)
		close(refreshDone)
	}()
	select {
	case <-refreshDone:
	case <-time.After(50 * time.Millisecond):
	}
	close(payloadService.release)
	<-eventDone
	<-refreshDone

	service.HandleExecutionPayloadAvailableEvent(ctx, &apiv1.ExecutionPayloadAvailableEvent{Slot: 0})

	require.Equal(t, int32(1), payloadService.calls.Load())
}

func TestRefreshPayloadAttestationsReplacesDutyBeforeWaitingEventRuns(t *testing.T) {
	ctx := context.Background()
	schedulerService := &recordingScheduler{}
	payloadService := &recordingPayloadAttester{}
	service := &Service{
		chainTimeService:           currentSlotRecordingChainTime(0),
		ptcDutiesProvider:          &recordingPTCDutiesProvider{duties: []*apiv1.PTCDuty{{Slot: 0, ValidatorIndex: 2}}},
		validatingAccountsProvider: &recordingAccountsProvider{epochIndices: []phase0.ValidatorIndex{2}},
		scheduler:                  schedulerService,
		payloadAttester:            payloadService,
		payloadAttestationDelay:    9 * time.Second,
		gloasForkEpoch:             0,
	}
	oldDuty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 0, ValidatorIndex: 1})
	service.schedulePayloadAttestation(ctx, oldDuty, map[phase0.ValidatorIndex]e2wtypes.Account{1: nil})
	oldAttestation := service.payloadAttestations[0]
	oldAttestation.mutex.Lock()

	refreshDone := make(chan struct{})
	go func() {
		service.refreshPayloadAttestationDutiesForEpoch(ctx, 0)
		close(refreshDone)
	}()
	require.Eventually(t, func() bool {
		return goroutineBlockedOnMutex("refreshPayloadAttestationDutiesForEpoch")
	}, time.Second, time.Millisecond)

	eventDone := make(chan struct{})
	go func() {
		service.HandleExecutionPayloadAvailableEvent(ctx, &apiv1.ExecutionPayloadAvailableEvent{Slot: 0})
		close(eventDone)
	}()
	require.Eventually(t, func() bool {
		return goroutineBlockedOnMutex("HandleExecutionPayloadAvailableEvent")
	}, time.Second, time.Millisecond)

	oldAttestation.mutex.Unlock()
	<-refreshDone
	<-eventDone
	service.HandleExecutionPayloadAvailableEvent(ctx, &apiv1.ExecutionPayloadAvailableEvent{Slot: 0})

	require.Len(t, payloadService.duties, 1)
	require.Equal(t, []phase0.ValidatorIndex{2}, payloadService.duties[0].ValidatorIndices())
}

func TestRefreshPayloadAttestationsRemovesCancelledEventAttempt(t *testing.T) {
	ctx := context.Background()
	schedulerService := &recordingScheduler{}
	payloadService := &recordingPayloadAttester{}
	service := &Service{
		chainTimeService:           &recordingChainTime{currentEpoch: 0, slotDuration: time.Second, slotsPerEpoch: 32},
		ptcDutiesProvider:          &recordingPTCDutiesProvider{},
		validatingAccountsProvider: &recordingAccountsProvider{},
		scheduler:                  schedulerService,
		payloadAttester:            payloadService,
		gloasForkEpoch:             0,
	}
	duty := payloadattester.NewDuty(&apiv1.PTCDuty{Slot: 10, ValidatorIndex: 1})
	service.schedulePayloadAttestation(ctx, duty, map[phase0.ValidatorIndex]e2wtypes.Account{1: nil})

	service.refreshPayloadAttestationDutiesForEpoch(ctx, 0)
	service.HandleExecutionPayloadAvailableEvent(ctx, &apiv1.ExecutionPayloadAvailableEvent{Slot: 10})

	require.Empty(t, payloadService.duties)
}

func TestRefreshPayloadAttestationsReschedulesAfterDependentRootChange(t *testing.T) {
	schedulerService := &recordingScheduler{existing: map[string]bool{payloadAttestationJobName(10): true}}
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

// TestSchedulePayloadAttestationsDoesNotRescheduleCurrentEpoch confirms that the epoch ticker does
// not refetch and reschedule an epoch that the preceding epoch's preparation already scheduled.
// Both call sites reach the same epoch, and the scheduler rejects a job that already exists, so
// without this every payload attestation duty would fail to schedule once per epoch.
func TestSchedulePayloadAttestationsDoesNotRescheduleCurrentEpoch(t *testing.T) {
	provider := &recordingPTCDutiesProvider{duties: []*apiv1.PTCDuty{{Slot: 10, ValidatorIndex: 1}}}
	schedulerService := &recordingScheduler{existing: map[string]bool{"Payload attestations for slot 10": true}}
	service := &Service{
		chainTimeService:           &recordingChainTime{currentEpoch: 0, slotsPerEpoch: 32},
		ptcDutiesProvider:          provider,
		validatingAccountsProvider: &recordingAccountsProvider{},
		scheduler:                  schedulerService,
		payloadAttester:            &recordingPayloadAttester{},
		gloasForkEpoch:             0,
	}

	service.schedulePayloadAttestations(context.Background(), 0, []phase0.ValidatorIndex{1}, false)

	require.Equal(t, 0, provider.calls)
	require.Empty(t, schedulerService.jobs)
}

// TestSchedulePayloadAttestationsSchedulesFirstGloasEpochBeforeTheFork confirms that the first Gloas
// epoch's duties are scheduled from the epoch before the fork, where they are prepared.  Testing the
// current epoch rather than the epoch being scheduled would drop that whole epoch's duties.
func TestSchedulePayloadAttestationsSchedulesFirstGloasEpochBeforeTheFork(t *testing.T) {
	provider := &recordingPTCDutiesProvider{duties: []*apiv1.PTCDuty{{Slot: 165, ValidatorIndex: 1}}}
	schedulerService := &recordingScheduler{}
	service := &Service{
		chainTimeService:           &recordingChainTime{currentEpoch: 4, slotDuration: time.Second, slotsPerEpoch: 32},
		ptcDutiesProvider:          provider,
		validatingAccountsProvider: &recordingAccountsProvider{},
		scheduler:                  schedulerService,
		payloadAttester:            &recordingPayloadAttester{},
		gloasForkEpoch:             5,
	}

	service.schedulePayloadAttestations(context.Background(), 5, []phase0.ValidatorIndex{1}, true)

	require.Equal(t, 1, provider.calls)
	require.Len(t, schedulerService.jobs, 1)
}

// TestRefreshPayloadAttestationsDoesNotRerunTheCurrentSlot confirms that a refresh does not
// reschedule the current slot's duty when its job has already run.  The scheduler runs a job whose
// time has passed immediately, so rescheduling it would attest to the same slot's payload twice.
func TestRefreshPayloadAttestationsDoesNotRerunTheCurrentSlot(t *testing.T) {
	schedulerService := &recordingScheduler{missing: map[string]bool{"Payload attestations for slot 32": true}}
	service := &Service{
		chainTimeService: &recordingChainTime{currentEpoch: 1, slotDuration: time.Second, slotsPerEpoch: 32},
		ptcDutiesProvider: &recordingPTCDutiesProvider{duties: []*apiv1.PTCDuty{
			{Slot: 32, ValidatorIndex: 1},
			{Slot: 33, ValidatorIndex: 1},
		}},
		validatingAccountsProvider: &recordingAccountsProvider{epochIndices: []phase0.ValidatorIndex{1}},
		scheduler:                  schedulerService,
		payloadAttester:            &recordingPayloadAttester{},
		gloasForkEpoch:             0,
	}

	service.refreshPayloadAttestationDutiesForEpoch(context.Background(), 1)

	require.Len(t, schedulerService.jobs, 1)
	require.Equal(t, service.chainTimeService.StartOfSlot(33), schedulerService.jobs[0].runtime)
}

// TestRefreshPayloadAttestationsWaitsForEpochPreparation confirms that a refresh of an epoch that
// has not yet been prepared leaves it alone, rather than fetching its duties early.
func TestRefreshPayloadAttestationsWaitsForEpochPreparation(t *testing.T) {
	provider := &recordingPTCDutiesProvider{duties: []*apiv1.PTCDuty{{Slot: 40, ValidatorIndex: 1}}}
	schedulerService := &recordingScheduler{existing: map[string]bool{"Prepare for epoch 1": true}}
	service := &Service{
		chainTimeService:           &recordingChainTime{currentEpoch: 0, slotsPerEpoch: 32},
		ptcDutiesProvider:          provider,
		validatingAccountsProvider: &recordingAccountsProvider{epochIndices: []phase0.ValidatorIndex{1}},
		scheduler:                  schedulerService,
		payloadAttester:            &recordingPayloadAttester{},
		gloasForkEpoch:             0,
	}

	service.refreshPayloadAttestationDutiesForEpoch(context.Background(), 1)

	require.Equal(t, 0, provider.calls)
	require.Empty(t, schedulerService.cancelled)
	require.Empty(t, schedulerService.jobs)
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
	mutex     sync.Mutex
	jobs      []recordedJob
	cancelled []string
	err       error
	existing  map[string]bool
	// missing names the jobs for which a cancellation reports that no such job exists, standing
	// in for a job that has already run.
	missing map[string]bool
}

type recordedJob struct {
	name    string
	runtime time.Time
	job     scheduler.JobFunc
}

func (s *recordingScheduler) ScheduleJob(_ context.Context, _ string, name string, runtime time.Time, job scheduler.JobFunc) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.existing == nil {
		s.existing = make(map[string]bool)
	}
	s.existing[name] = true
	s.jobs = append(s.jobs, recordedJob{name: name, runtime: runtime, job: job})
	return nil
}

func (*recordingScheduler) SchedulePeriodicJob(context.Context, string, string, scheduler.RuntimeFunc, scheduler.JobFunc) error {
	return nil
}

func (s *recordingScheduler) CancelJob(_ context.Context, name string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.missing[name] || !s.existing[name] {
		return scheduler.ErrNoSuchJob
	}
	delete(s.existing, name)
	s.cancelled = append(s.cancelled, name)
	return nil
}
func (s *recordingScheduler) CancelJobIfExists(_ context.Context, name string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.existing[name] {
		s.cancelled = append(s.cancelled, name)
		delete(s.existing, name)
	}
}
func (*recordingScheduler) CancelJobs(context.Context, string)   {}
func (*recordingScheduler) RunJob(context.Context, string) error { return nil }
func (s *recordingScheduler) JobExists(_ context.Context, name string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.existing[name]
}
func (s *recordingScheduler) RunJobIfExists(ctx context.Context, name string) {
	s.mutex.Lock()
	if !s.existing[name] {
		s.mutex.Unlock()
		return
	}
	delete(s.existing, name)
	var jobFunc scheduler.JobFunc
	for _, job := range s.jobs {
		if job.name == name {
			jobFunc = job.job
			break
		}
	}
	s.mutex.Unlock()
	if jobFunc != nil {
		jobFunc(ctx)
	}
}
func (*recordingScheduler) ListJobs(context.Context) []string { return nil }

type blockingPayloadAttester struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (*blockingPayloadAttester) Prepare(context.Context, *payloadattester.Duty) error {
	return nil
}

func (s *blockingPayloadAttester) Attest(context.Context, *payloadattester.Duty) ([]*spec.VersionedPayloadAttestationMessage, error) {
	if s.calls.Add(1) == 1 {
		close(s.started)
		<-s.release
	}
	return nil, nil
}

type recordingPayloadAttester struct {
	duties   []*payloadattester.Duty
	prepared []*payloadattester.Duty
	deadline time.Time
	err      error
}

func (s *recordingPayloadAttester) Prepare(_ context.Context, duty *payloadattester.Duty) error {
	s.prepared = append(s.prepared, duty)
	return nil
}

func (s *recordingPayloadAttester) Attest(ctx context.Context, duty *payloadattester.Duty) ([]*spec.VersionedPayloadAttestationMessage, error) {
	s.deadline, _ = ctx.Deadline()
	s.duties = append(s.duties, duty)
	return nil, s.err
}

type recordingChainTime struct {
	genesisTime   time.Time
	currentEpoch  phase0.Epoch
	slotDuration  time.Duration
	slotsPerEpoch uint64
}

func (s *recordingChainTime) GenesisTime() time.Time {
	if s.genesisTime.IsZero() {
		return time.Unix(0, 0)
	}
	return s.genesisTime
}
func (s *recordingChainTime) StartOfSlot(slot phase0.Slot) time.Time {
	return s.GenesisTime().Add(time.Duration(slot) * s.slotDuration)
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

func goroutineBlockedOnMutex(function string) bool {
	stacks := make([]byte, 1<<20)
	length := runtime.Stack(stacks, true)
	for _, stack := range strings.Split(string(stacks[:length]), "\n\n") {
		if strings.Contains(stack, function) && strings.Contains(stack, "sync.(*Mutex).Lock") {
			return true
		}
	}
	return false
}

func currentSlotRecordingChainTime(slot phase0.Slot) *recordingChainTime {
	slotDuration := 12 * time.Second
	return &recordingChainTime{
		genesisTime:   time.Now().Add(-time.Duration(slot) * slotDuration),
		slotDuration:  slotDuration,
		slotsPerEpoch: 32,
	}
}
