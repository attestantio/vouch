// Copyright © 2026 Attestant Limited.
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

package multinode_test

import (
	"context"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	prometheusmetrics "github.com/attestantio/vouch/services/metrics/prometheus"
	"github.com/attestantio/vouch/services/submitter/multinode"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSubmitExecutionPayloadEnvelopeReportsProviderResults(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	monitor, err := prometheusmetrics.New(ctx,
		prometheusmetrics.WithLogLevel(zerolog.Disabled),
		prometheusmetrics.WithAddress("localhost:0"),
	)
	require.NoError(t, err)
	beaconBlockRoot := phase0.Root{0x01}
	failingAddress := "https://user:secret@failed.example/path?access_token=secret"
	workingAddress := "http://working.example"
	failingProviderCountBefore := clientOperationCount(t, "https://user:xxxxx@failed.example/xxxxx?access_token=xxxxx", "submit execution payload envelope", "failed")
	workingProviderCountBefore := clientOperationCount(t, workingAddress, "submit execution payload envelope", "succeeded")
	unaddressedProviderCountBefore := clientOperationCount(t, "http://<unknown>", "submit execution payload envelope", "succeeded")
	service, err := multinode.New(ctx,
		multinode.WithLogLevel(zerolog.TraceLevel),
		multinode.WithClientMonitor(monitor),
		multinode.WithTimeout(time.Second),
		multinode.WithProcessConcurrency(2),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"one": mock.NewProposalSubmitter(),
		}),
		multinode.WithExecutionPayloadEnvelopeSubmitters(map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{
			"failing":     &serviceExecutionPayloadEnvelopeSubmitter{address: failingAddress, err: &api.Error{StatusCode: 400}},
			"working":     &serviceExecutionPayloadEnvelopeSubmitter{address: workingAddress},
			"unaddressed": &capturingExecutionPayloadEnvelopeSubmitter{},
		}),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"one": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"one": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"one": mock.NewAggregateAttestationsSubmitter(),
		}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{
			"one": mock.NewProposalPreparationsSubmitter(),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"one": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"one": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"one": mock.NewSyncCommitteeContributionsSubmitter(),
		}),
	)
	require.NoError(t, err)

	err = service.SubmitExecutionPayloadEnvelope(ctx, &api.SubmitExecutionPayloadEnvelopeOpts{
		SignedExecutionPayloadEnvelope: &spec.VersionedSignedExecutionPayloadEnvelope{
			Version: spec.DataVersionGloas,
			Gloas: &gloas.SignedExecutionPayloadEnvelope{
				Message: &gloas.ExecutionPayloadEnvelope{BeaconBlockRoot: beaconBlockRoot},
			},
		},
	})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return capture.HasLog(map[string]any{
			"message":             "Execution payload envelope provider submission completed",
			"beacon_node_address": "failing",
			"beacon_block_root":   beaconBlockRoot.String(),
			"status":              "failed",
			"status_code":         400,
		}) && hasProviderSubmissionField(capture, "failing", beaconBlockRoot.String(), "failed", "elapsed") &&
			hasProviderSubmissionField(capture, "failing", beaconBlockRoot.String(), "failed", "error")
	}, time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		return capture.HasLog(map[string]any{
			"message":             "Execution payload envelope provider submission completed",
			"beacon_node_address": "working",
			"beacon_block_root":   beaconBlockRoot.String(),
			"status":              "succeeded",
		}) && hasProviderSubmissionField(capture, "working", beaconBlockRoot.String(), "succeeded", "elapsed")
	}, time.Second, 10*time.Millisecond)
	for _, entry := range capture.Entries() {
		for _, value := range entry {
			require.NotEqual(t, failingAddress, value)
		}
	}
	require.Eventually(t, func() bool {
		return clientOperationCount(t, "https://user:xxxxx@failed.example/xxxxx?access_token=xxxxx", "submit execution payload envelope", "failed") == failingProviderCountBefore+1 &&
			clientOperationCount(t, workingAddress, "submit execution payload envelope", "succeeded") == workingProviderCountBefore+1 &&
			clientOperationCount(t, "http://<unknown>", "submit execution payload envelope", "succeeded") == unaddressedProviderCountBefore+1
	}, time.Second, 10*time.Millisecond)
	require.Zero(t, clientOperationCount(t, "http://unaddressed", "submit execution payload envelope", "succeeded"))
}

func TestSubmitExecutionPayloadEnvelopeReturnsPromptlyAfterImmediateSuccess(t *testing.T) {
	ctx := context.Background()
	capture := &capturingExecutionPayloadEnvelopeSubmitter{}
	service, err := multinode.New(ctx,
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(time.Second),
		multinode.WithProcessConcurrency(1),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"one": mock.NewProposalSubmitter(),
		}),
		multinode.WithExecutionPayloadEnvelopeSubmitters(map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{
			"one": capture,
		}),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"one": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"one": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"one": mock.NewAggregateAttestationsSubmitter(),
		}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{
			"one": mock.NewProposalPreparationsSubmitter(),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"one": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"one": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"one": mock.NewSyncCommitteeContributionsSubmitter(),
		}),
	)
	require.NoError(t, err)

	opts := &api.SubmitExecutionPayloadEnvelopeOpts{}
	started := time.Now()
	require.NoError(t, service.SubmitExecutionPayloadEnvelope(ctx, opts))
	require.Less(t, time.Since(started), 100*time.Millisecond)
	require.Same(t, opts, capture.opts)
}

func TestSubmitExecutionPayloadEnvelopeDoesNotWaitForNodeVersion(t *testing.T) {
	ctx := context.Background()
	nodeVersionRelease := make(chan struct{})
	submitter := &nodeVersionBlockingExecutionPayloadEnvelopeSubmitter{
		envelopeStarted:    make(chan struct{}, 1),
		nodeVersionStarted: make(chan struct{}, 1),
		nodeVersionRelease: nodeVersionRelease,
	}
	defer close(nodeVersionRelease)
	service, err := multinode.New(ctx,
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(time.Second),
		multinode.WithProcessConcurrency(1),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"one": mock.NewProposalSubmitter(),
		}),
		multinode.WithExecutionPayloadEnvelopeSubmitters(map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{
			"one": submitter,
		}),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"one": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"one": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"one": mock.NewAggregateAttestationsSubmitter(),
		}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{
			"one": mock.NewProposalPreparationsSubmitter(),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"one": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"one": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"one": mock.NewSyncCommitteeContributionsSubmitter(),
		}),
	)
	require.NoError(t, err)

	result := make(chan error, 1)
	go func() {
		result <- service.SubmitExecutionPayloadEnvelope(ctx, &api.SubmitExecutionPayloadEnvelopeOpts{})
	}()

	select {
	case <-submitter.envelopeStarted:
		require.NoError(t, <-result)
	case <-submitter.nodeVersionStarted:
		t.Fatal("submission waited for node version")
	case <-time.After(time.Second):
		t.Fatal("submission did not start")
	}
}

// TestSubmitExecutionPayloadEnvelopeIdentifiesProviderThatNeverStarts covers the provider that
// leaves through the semaphore rather than through a submission: with a single concurrency slot
// held until the deadline, the queued provider must still be identifiable in the log.
func TestSubmitExecutionPayloadEnvelopeIdentifiesProviderThatNeverStarts(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	canceled := make(chan struct{}, 2)
	beaconBlockRoot := phase0.Root{0x03}
	service, err := multinode.New(ctx,
		multinode.WithLogLevel(zerolog.TraceLevel),
		multinode.WithTimeout(50*time.Millisecond),
		multinode.WithProcessConcurrency(1),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"one": mock.NewProposalSubmitter(),
		}),
		multinode.WithExecutionPayloadEnvelopeSubmitters(map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{
			"one": &blockingExecutionPayloadEnvelopeSubmitter{canceled: canceled},
			"two": &blockingExecutionPayloadEnvelopeSubmitter{canceled: canceled},
		}),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"one": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"one": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"one": mock.NewAggregateAttestationsSubmitter(),
		}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{
			"one": mock.NewProposalPreparationsSubmitter(),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"one": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"one": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"one": mock.NewSyncCommitteeContributionsSubmitter(),
		}),
	)
	require.NoError(t, err)

	// Only one of the two providers takes the single slot; the other never starts its
	// submission, so its only record is the semaphore failure.
	err = service.SubmitExecutionPayloadEnvelope(ctx, &api.SubmitExecutionPayloadEnvelopeOpts{
		SignedExecutionPayloadEnvelope: &spec.VersionedSignedExecutionPayloadEnvelope{
			Version: spec.DataVersionGloas,
			Gloas: &gloas.SignedExecutionPayloadEnvelope{
				Message: &gloas.ExecutionPayloadEnvelope{BeaconBlockRoot: beaconBlockRoot},
			},
		},
	})
	require.EqualError(t, err, "no successful submissions before timeout")
	require.Eventually(t, func() bool {
		for _, name := range []string{"one", "two"} {
			if capture.HasLog(map[string]any{
				"message":             "Failed to acquire semaphore",
				"beacon_node_address": name,
				"beacon_block_root":   beaconBlockRoot.String(),
			}) {
				return true
			}
		}

		return false
	}, time.Second, 10*time.Millisecond)
}

func TestSubmitExecutionPayloadEnvelopeCancelsOnDeadline(t *testing.T) {
	ctx := context.Background()
	canceled := make(chan struct{}, 1)
	service, err := multinode.New(ctx,
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(50*time.Millisecond),
		multinode.WithProcessConcurrency(1),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"one": mock.NewProposalSubmitter(),
		}),
		multinode.WithExecutionPayloadEnvelopeSubmitters(map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{
			"one": &blockingExecutionPayloadEnvelopeSubmitter{canceled: canceled},
		}),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"one": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"one": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"one": mock.NewAggregateAttestationsSubmitter(),
		}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{
			"one": mock.NewProposalPreparationsSubmitter(),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"one": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"one": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"one": mock.NewSyncCommitteeContributionsSubmitter(),
		}),
	)
	require.NoError(t, err)

	err = service.SubmitExecutionPayloadEnvelope(ctx, &api.SubmitExecutionPayloadEnvelopeOpts{})
	require.EqualError(t, err, "no successful submissions before timeout")
	require.Eventually(t, func() bool {
		select {
		case <-canceled:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestSubmitExecutionPayloadEnvelopeLetsSlowSubmitterCompleteAfterFirstSuccess(t *testing.T) {
	ctx := context.Background()
	completed := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	fast := &capturingExecutionPayloadEnvelopeSubmitter{}
	slow := &slowExecutionPayloadEnvelopeSubmitter{
		delay:     100 * time.Millisecond,
		completed: completed,
		cancelled: cancelled,
	}
	service, err := multinode.New(ctx,
		multinode.WithLogLevel(zerolog.Disabled),
		multinode.WithTimeout(time.Second),
		multinode.WithProcessConcurrency(2),
		multinode.WithProposalSubmitters(map[string]eth2client.ProposalSubmitter{
			"one": mock.NewProposalSubmitter(),
		}),
		multinode.WithExecutionPayloadEnvelopeSubmitters(map[string]eth2client.ExecutionPayloadEnvelopeSubmitter{
			"fast": fast,
			"slow": slow,
		}),
		multinode.WithAttestationsSubmitters(map[string]eth2client.AttestationsSubmitter{
			"one": mock.NewAttestationsSubmitter(),
		}),
		multinode.WithBeaconCommitteeSubscriptionsSubmitters(map[string]eth2client.BeaconCommitteeSubscriptionsSubmitter{
			"one": mock.NewBeaconCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithAggregateAttestationsSubmitters(map[string]eth2client.AggregateAttestationsSubmitter{
			"one": mock.NewAggregateAttestationsSubmitter(),
		}),
		multinode.WithProposalPreparationsSubmitters(map[string]eth2client.ProposalPreparationsSubmitter{
			"one": mock.NewProposalPreparationsSubmitter(),
		}),
		multinode.WithSyncCommitteeMessagesSubmitters(map[string]eth2client.SyncCommitteeMessagesSubmitter{
			"one": mock.NewSyncCommitteeMessagesSubmitter(),
		}),
		multinode.WithSyncCommitteeSubscriptionsSubmitters(map[string]eth2client.SyncCommitteeSubscriptionsSubmitter{
			"one": mock.NewSyncCommitteeSubscriptionsSubmitter(),
		}),
		multinode.WithSyncCommitteeContributionsSubmitters(map[string]eth2client.SyncCommitteeContributionsSubmitter{
			"one": mock.NewSyncCommitteeContributionsSubmitter(),
		}),
	)
	require.NoError(t, err)

	require.NoError(t, service.SubmitExecutionPayloadEnvelope(ctx, &api.SubmitExecutionPayloadEnvelopeOpts{}))

	select {
	case <-completed:
		// The slow submitter finished its own submission, as required: the fast peer's
		// success must not abort it.
	case <-cancelled:
		t.Fatal("slow submitter was cancelled instead of completing its submission")
	case <-time.After(time.Second):
		t.Fatal("slow submitter did not finish its submission")
	}
}

type capturingExecutionPayloadEnvelopeSubmitter struct {
	opts *api.SubmitExecutionPayloadEnvelopeOpts
}

func (s *capturingExecutionPayloadEnvelopeSubmitter) SubmitExecutionPayloadEnvelope(_ context.Context, opts *api.SubmitExecutionPayloadEnvelopeOpts) error {
	s.opts = opts
	return nil
}

// serviceExecutionPayloadEnvelopeSubmitter is an envelope submitter that is also an
// eth2client.Service, so that its address rather than its name reaches the client monitor.
type serviceExecutionPayloadEnvelopeSubmitter struct {
	address string
	err     error
}

func (s *serviceExecutionPayloadEnvelopeSubmitter) SubmitExecutionPayloadEnvelope(_ context.Context, _ *api.SubmitExecutionPayloadEnvelopeOpts) error {
	return s.err
}

func (*serviceExecutionPayloadEnvelopeSubmitter) Name() string {
	return "service"
}

func (s *serviceExecutionPayloadEnvelopeSubmitter) Address() string {
	return s.address
}

func (*serviceExecutionPayloadEnvelopeSubmitter) IsActive() bool {
	return true
}

func (*serviceExecutionPayloadEnvelopeSubmitter) IsSynced() bool {
	return true
}

func clientOperationCount(t *testing.T, provider string, operation string, result string) float64 {
	t.Helper()

	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, metricFamily := range metricFamilies {
		if metricFamily.GetName() != "vouch_client_operation_requests_total" {
			continue
		}
		for _, metric := range metricFamily.GetMetric() {
			var providerMatches, operationMatches, resultMatches bool
			for _, label := range metric.GetLabel() {
				switch label.GetName() {
				case "provider":
					providerMatches = label.GetValue() == provider
				case "operation":
					operationMatches = label.GetValue() == operation
				case "result":
					resultMatches = label.GetValue() == result
				}
			}
			if providerMatches && operationMatches && resultMatches {
				return metric.GetCounter().GetValue()
			}
		}
	}

	return 0
}

func hasProviderSubmissionField(capture *logger.LogCapture, beaconNodeAddress string, beaconBlockRoot string, status string, field string) bool {
	for _, entry := range capture.Entries() {
		if entry["message"] != "Execution payload envelope provider submission completed" ||
			entry["beacon_node_address"] != beaconNodeAddress ||
			entry["beacon_block_root"] != beaconBlockRoot ||
			entry["status"] != status {
			continue
		}
		if _, exists := entry[field]; exists {
			return true
		}
	}

	return false
}

type blockingExecutionPayloadEnvelopeSubmitter struct {
	canceled chan<- struct{}
}

func (s *blockingExecutionPayloadEnvelopeSubmitter) SubmitExecutionPayloadEnvelope(ctx context.Context,
	_ *api.SubmitExecutionPayloadEnvelopeOpts,
) error {
	<-ctx.Done()
	s.canceled <- struct{}{}
	return ctx.Err()
}

type nodeVersionBlockingExecutionPayloadEnvelopeSubmitter struct {
	envelopeStarted    chan struct{}
	nodeVersionStarted chan struct{}
	nodeVersionRelease <-chan struct{}
}

func (s *nodeVersionBlockingExecutionPayloadEnvelopeSubmitter) SubmitExecutionPayloadEnvelope(
	_ context.Context,
	_ *api.SubmitExecutionPayloadEnvelopeOpts,
) error {
	s.envelopeStarted <- struct{}{}
	return nil
}

func (*nodeVersionBlockingExecutionPayloadEnvelopeSubmitter) Name() string {
	return "test"
}

func (*nodeVersionBlockingExecutionPayloadEnvelopeSubmitter) Address() string {
	return "http://test"
}

func (*nodeVersionBlockingExecutionPayloadEnvelopeSubmitter) IsActive() bool {
	return true
}

func (*nodeVersionBlockingExecutionPayloadEnvelopeSubmitter) IsSynced() bool {
	return true
}

func (s *nodeVersionBlockingExecutionPayloadEnvelopeSubmitter) NodeVersion(
	_ context.Context,
	_ *api.NodeVersionOpts,
) (*api.Response[string], error) {
	s.nodeVersionStarted <- struct{}{}
	<-s.nodeVersionRelease
	return &api.Response[string]{Data: "test"}, nil
}

type slowExecutionPayloadEnvelopeSubmitter struct {
	delay     time.Duration
	completed chan<- struct{}
	cancelled chan<- struct{}
}

func (s *slowExecutionPayloadEnvelopeSubmitter) SubmitExecutionPayloadEnvelope(ctx context.Context,
	_ *api.SubmitExecutionPayloadEnvelopeOpts,
) error {
	select {
	case <-time.After(s.delay):
		s.completed <- struct{}{}
		return nil
	case <-ctx.Done():
		s.cancelled <- struct{}{}
		return ctx.Err()
	}
}

var _ eth2client.ExecutionPayloadEnvelopeSubmitter = (*capturingExecutionPayloadEnvelopeSubmitter)(nil)
var _ eth2client.ExecutionPayloadEnvelopeSubmitter = (*slowExecutionPayloadEnvelopeSubmitter)(nil)
var _ eth2client.ExecutionPayloadEnvelopeSubmitter = (*nodeVersionBlockingExecutionPayloadEnvelopeSubmitter)(nil)
var _ eth2client.NodeVersionProvider = (*nodeVersionBlockingExecutionPayloadEnvelopeSubmitter)(nil)
var _ eth2client.Service = (*nodeVersionBlockingExecutionPayloadEnvelopeSubmitter)(nil)
