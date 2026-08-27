// Copyright © 2026 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");

package standard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/payloadattester"
	payloadattesterstandard "github.com/attestantio/vouch/services/payloadattester/standard"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/attestantio/vouch/testutil"
	"github.com/rs/zerolog"
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

func TestScheduledPayloadAttestationFetchesBatchedSignsAndSubmits(t *testing.T) {
	ctx := context.Background()
	accounts, err := testutil.CreateTestWalletAndAccounts([]phase0.ValidatorIndex{1, 2}, "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
	require.NoError(t, err)
	data := &gloas.PayloadAttestationData{BeaconBlockRoot: phase0.Root{0x01}, Slot: 10, PayloadPresent: true}
	dataProvider := &recordingPayloadAttestationDataProvider{data: data}
	signer := &recordingPayloadAttestationDataSigner{}
	submitter := &recordingPayloadAttestationMessagesSubmitter{}
	payloadService, err := payloadattesterstandard.New(ctx,
		payloadattesterstandard.WithLogLevel(zerolog.Disabled),
		payloadattesterstandard.WithMonitor(prometheusMonitor{}),
		payloadattesterstandard.WithPayloadAttestationDataProvider(dataProvider),
		payloadattesterstandard.WithPayloadAttestationDataSigner(signer),
		payloadattesterstandard.WithPayloadAttestationMessagesSubmitter(submitter),
	)
	require.NoError(t, err)
	schedulerService := &recordingScheduler{}
	service := &Service{
		chainTimeService:           &recordingChainTime{slotDuration: time.Second, slotsPerEpoch: 32},
		ptcDutiesProvider:          &recordingPTCDutiesProvider{duties: []*apiv1.PTCDuty{{Slot: 10, ValidatorIndex: 1}, {Slot: 10, ValidatorIndex: 2}}},
		validatingAccountsProvider: &recordingAccountsProvider{accounts: accounts},
		scheduler:                  schedulerService,
		payloadAttester:            payloadService,
		payloadAttestationDelay:    750 * time.Millisecond,
		gloasForkEpoch:             0,
	}

	service.schedulePayloadAttestations(ctx, 0, []phase0.ValidatorIndex{1, 2}, false)
	require.Len(t, schedulerService.jobs, 1)

	schedulerService.jobs[0].job(ctx)

	require.Equal(t, []phase0.Slot{10}, dataProvider.slots)
	require.Equal(t, 1, signer.calls)
	require.Equal(t, accounts[1], signer.accounts[0])
	require.Equal(t, accounts[2], signer.accounts[1])
	require.Same(t, data, signer.data)
	require.Len(t, submitter.messages, 2)
	require.Equal(t, &spec.VersionedPayloadAttestationMessage{
		Version: spec.DataVersionGloas,
		Gloas: &gloas.PayloadAttestationMessage{
			ValidatorIndex: 1,
			Data:           data,
			Signature:      phase0.BLSSignature{0x01},
		},
	}, submitter.messages[0])
	require.Equal(t, &spec.VersionedPayloadAttestationMessage{
		Version: spec.DataVersionGloas,
		Gloas: &gloas.PayloadAttestationMessage{
			ValidatorIndex: 2,
			Data:           data,
			Signature:      phase0.BLSSignature{0x02},
		},
	}, submitter.messages[1])
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
	require.Equal(t, chainTime.StartOfSlot(10).Add(9*time.Second+250*time.Millisecond), schedulerService.jobs[0].runtime)
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
	require.Equal(t, service.chainTimeService.StartOfSlot(33).Add(payloadAttestationGrace), schedulerService.jobs[0].runtime)
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
	accounts     map[phase0.ValidatorIndex]e2wtypes.Account
	indices      []phase0.ValidatorIndex
	epochIndices []phase0.ValidatorIndex
}

func (p *recordingAccountsProvider) ValidatingAccountsForEpoch(_ context.Context, _ phase0.Epoch) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	return p.accountsFor(p.epochIndices), nil
}

func (p *recordingAccountsProvider) ValidatingAccountsForEpochByIndex(_ context.Context, _ phase0.Epoch, indices []phase0.ValidatorIndex) (map[phase0.ValidatorIndex]e2wtypes.Account, error) {
	p.indices = append([]phase0.ValidatorIndex(nil), indices...)
	return p.accountsFor(indices), nil
}

func (p *recordingAccountsProvider) accountsFor(indices []phase0.ValidatorIndex) map[phase0.ValidatorIndex]e2wtypes.Account {
	accounts := make(map[phase0.ValidatorIndex]e2wtypes.Account, len(indices))
	for _, index := range indices {
		accounts[index] = p.accounts[index]
	}
	return accounts
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
	err       error
	existing  map[string]bool
	// missing names the jobs for which a cancellation reports that no such job exists, standing
	// in for a job that has already run.
	missing map[string]bool
}

type recordedJob struct {
	runtime time.Time
	job     scheduler.JobFunc
}

func (s *recordingScheduler) ScheduleJob(_ context.Context, _ string, _ string, runtime time.Time, job scheduler.JobFunc) error {
	if s.err != nil {
		return s.err
	}
	s.jobs = append(s.jobs, recordedJob{runtime: runtime, job: job})
	return nil
}

func (*recordingScheduler) SchedulePeriodicJob(context.Context, string, string, scheduler.RuntimeFunc, scheduler.JobFunc) error {
	return nil
}

func (s *recordingScheduler) CancelJob(_ context.Context, name string) error {
	if s.missing[name] {
		return scheduler.ErrNoSuchJob
	}
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
	prepared []*payloadattester.Duty
	deadline time.Time
}

func (s *recordingPayloadAttester) Prepare(_ context.Context, duty *payloadattester.Duty) error {
	s.prepared = append(s.prepared, duty)
	return nil
}

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

type prometheusMonitor struct{}

func (prometheusMonitor) Presenter() string {
	return "prometheus"
}

type recordingPayloadAttestationDataProvider struct {
	data  *gloas.PayloadAttestationData
	slots []phase0.Slot
}

func (p *recordingPayloadAttestationDataProvider) PayloadAttestationData(_ context.Context, opts *api.PayloadAttestationDataOpts) (*api.Response[*spec.VersionedPayloadAttestationData], error) {
	p.slots = append(p.slots, opts.Slot)
	return &api.Response[*spec.VersionedPayloadAttestationData]{Data: &spec.VersionedPayloadAttestationData{
		Version: spec.DataVersionGloas,
		Gloas:   p.data,
	}}, nil
}

type recordingPayloadAttestationDataSigner struct {
	accounts []e2wtypes.Account
	calls    int
	data     *gloas.PayloadAttestationData
}

func (s *recordingPayloadAttestationDataSigner) SignPayloadAttestationData(_ context.Context, accounts []e2wtypes.Account, data *gloas.PayloadAttestationData) ([]phase0.BLSSignature, error) {
	s.calls++
	s.accounts = accounts
	s.data = data
	signatures := make([]phase0.BLSSignature, len(accounts))
	for i := range signatures {
		signatures[i][0] = byte(i + 1)
	}
	return signatures, nil
}

type recordingPayloadAttestationMessagesSubmitter struct {
	messages []*spec.VersionedPayloadAttestationMessage
}

func (s *recordingPayloadAttestationMessagesSubmitter) SubmitPayloadAttestationMessages(_ context.Context, opts *api.SubmitPayloadAttestationMessagesOpts) error {
	s.messages = opts.Messages
	return nil
}
