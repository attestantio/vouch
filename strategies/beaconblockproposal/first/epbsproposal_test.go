// Copyright © 2020 - 2026 Attestant Limited.
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

package first_test

import (
	"context"
	"errors"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	apiv1gloas "github.com/attestantio/go-eth2-client/api/v1/gloas"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/strategies/beaconblockproposal/first"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestEPBSProposalFansOutTheSameBuilderConfig(t *testing.T) {
	ctx := context.Background()
	config := &gloas.BuilderConfig{MinBid: 12, BuilderBoostFactor: 100, Builders: []*gloas.BuilderEntry{}}
	ready := make(chan struct{})
	var readyOnce sync.Once
	var mu sync.Mutex
	received := make([]*api.EPBSProposalOpts, 0, 2)
	provider := func(feeRecipient byte) beaconblockproposer.ProposalDataProvider {
		return &fanoutEPBSProposalProvider{
			proposal:  gloasEPBSProposal(bellatrix.ExecutionAddress{feeRecipient}),
			ready:     ready,
			readyOnce: &readyOnce,
			mu:        &mu,
			received:  &received,
		}
	}
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"one": provider(0x01),
			"two": provider(0x02),
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	_, err = service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, BuilderConfig: config})
	require.NoError(t, err)
	require.Len(t, received, 2)
	for i := range received {
		require.Same(t, config, received[i].BuilderConfig)
	}
}

type fanoutEPBSProposalProvider struct {
	proposal  *api.VersionedEPBSProposal
	ready     chan struct{}
	readyOnce *sync.Once
	mu        *sync.Mutex
	received  *[]*api.EPBSProposalOpts
}

func (p *fanoutEPBSProposalProvider) EPBSProposal(ctx context.Context, opts *api.EPBSProposalOpts) (*api.Response[*api.VersionedEPBSProposal], error) {
	p.mu.Lock()
	*p.received = append(*p.received, opts)
	if len(*p.received) == cap(*p.received) {
		p.readyOnce.Do(func() {
			close(p.ready)
		})
	}
	p.mu.Unlock()

	select {
	case <-p.ready:
		return &api.Response[*api.VersionedEPBSProposal]{Data: p.proposal}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *fanoutEPBSProposalProvider) Proposal(context.Context, *api.ProposalOpts) (*api.Response[*api.VersionedProposal], error) {
	return nil, nil
}

func TestEPBSProposalAcceptsUnknownValue(t *testing.T) {
	ctx := context.Background()

	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"one": &epbsProposalProvider{proposal: gloasEPBSProposal(bellatrix.ExecutionAddress{0x01})},
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot: phase0.Slot(1),
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.NotNil(t, response.Data)
	require.Nil(t, response.Data.ExecutionValue)
}

func TestEPBSProposalObservability(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	previousTracerProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(tracerProvider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previousTracerProvider)
		require.NoError(t, tracerProvider.Shutdown(ctx))
	})
	proposal := gloasEPBSProposalWithoutPayload(bellatrix.ExecutionAddress{0x01})
	proposal.ExecutionValue = big.NewInt(321)
	bodyRoot := phase0.Root{0x44}
	proposal.BeaconBlockBodyRoot = &bodyRoot
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.TraceLevel),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"stable-provider": &epbsProposalProvider{
				proposal: proposal,
				metadata: map[string]any{"Eth-Builder-Url": "https://builder.example"},
			},
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1})
	require.NoError(t, err)
	require.Equal(t, "first", response.Metadata["vouch.strategy"])
	require.Equal(t, "stable-provider", response.Metadata["vouch.provider"])
	require.Equal(t, "builder_api", response.Metadata["vouch.source"])
	require.True(t, capture.HasLog(map[string]any{
		"message":             "ePBS proposal provider completed",
		"slot":                uint64(1),
		"provider":            "stable-provider",
		"source":              "builder_api",
		"builder_index":       uint64(7),
		"value_known":         true,
		"execution_value":     "321",
		"payload_included":    false,
		"builder_url_present": true,
		"outcome":             "accepted",
		"rejection_reason":    "",
	}))
	require.Equal(t, false, response.Metadata["vouch.fallback"])

	for _, recordedSpan := range spanRecorder.Ended() {
		if recordedSpan.Name() != "EPBSProposal" && recordedSpan.Name() != "ePBSBeaconBlockProposal" {
			continue
		}
		attributes := make(map[string]any)
		for _, attr := range recordedSpan.Attributes() {
			attributes[string(attr.Key)] = attr.Value.AsInterface()
		}
		require.Equal(t, int64(1), attributes["slot"])
		require.NotEmpty(t, attributes["request_id"])
		require.Equal(t, "stable-provider", attributes["provider"])
		require.Equal(t, "builder_api", attributes["source"])
		require.NotEmpty(t, attributes["proposal_root"])
	}
}

func TestEPBSProposalReportsSimpleStrategy(t *testing.T) {
	ctx := context.Background()
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"simple": &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}},
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.NoError(t, err)
	require.Equal(t, "simple", response.Metadata["vouch.strategy"])
}

func TestEPBSProposalDoesNotLeaveLateProvidersBlocked(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	capture := logger.NewLogCapture()
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.TraceLevel),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"fast":      &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}},
			"cancelled": &epbsProposalProvider{waitForCancellation: true},
			"late1":     &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}, release: release},
			"late2":     &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}, release: release},
			"late-nil":  &epbsProposalProvider{release: release},
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.NoError(t, err)
	require.NotNil(t, response)
	close(release)

	require.Eventually(t, func() bool {
		stack := make([]byte, 64*1024)
		stackLength := runtime.Stack(stack, true)
		return !strings.Contains(string(stack[:stackLength]), "strategies/beaconblockproposal/first.(*Service).EPBSProposal.func1")
	}, time.Second, 10*time.Millisecond)
	for _, provider := range []string{"cancelled", "late1", "late2", "late-nil"} {
		require.Eventually(t, func() bool {
			return capture.HasLog(map[string]any{
				"message":          "ePBS proposal provider completed",
				"provider":         provider,
				"outcome":          "cancelled",
				"rejection_reason": "selection_completed",
			})
		}, time.Second, 10*time.Millisecond)
	}
}

func TestEPBSProposalFailureObservability(t *testing.T) {
	tests := []struct {
		name            string
		provider        *epbsProposalProvider
		readiness       *providerReadiness
		outcome         string
		rejectionReason string
	}{
		{
			name:            "ProviderError",
			provider:        &epbsProposalProvider{err: errors.New("connection failed")},
			outcome:         "error",
			rejectionReason: "provider_error",
		},
		{
			name:            "ProviderDeadline",
			provider:        &epbsProposalProvider{err: context.DeadlineExceeded},
			outcome:         "timeout",
			rejectionReason: "deadline_reached",
		},
		{
			name:            "Rejected",
			provider:        &epbsProposalProvider{proposal: gloasEPBSProposalWithoutPayload(bellatrix.ExecutionAddress{0x01})},
			readiness:       &providerReadiness{ready: false},
			outcome:         "rejected",
			rejectionReason: "provider_preferences_not_ready",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			capture := logger.NewLogCapture()
			service, err := first.New(ctx,
				first.WithLogLevel(zerolog.TraceLevel),
				first.WithClientMonitor(nullmetrics.New()),
				first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
					"failed-provider": test.provider,
				}),
				first.WithProviderReadiness(test.readiness),
				first.WithTimeout(10*time.Millisecond),
			)
			require.NoError(t, err)

			response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1})
			require.Nil(t, response)
			require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
			require.True(t, capture.HasLog(map[string]any{
				"message":          "ePBS proposal provider completed",
				"provider":         "failed-provider",
				"outcome":          test.outcome,
				"rejection_reason": test.rejectionReason,
			}))
			if test.outcome == "rejected" {
				var rejectionEntry map[string]any
				for _, entry := range capture.Entries() {
					if entry["message"] == "ePBS proposal provider completed" && entry["outcome"] == "rejected" {
						rejectionEntry = entry
						break
					}
				}
				require.NotNil(t, rejectionEntry)
				require.Equal(t, "p2p_builder", rejectionEntry["source"])
				require.Equal(t, float64(7), rejectionEntry["builder_index"])
				require.Equal(t, false, rejectionEntry["value_known"])
				require.Equal(t, "unknown", rejectionEntry["execution_value"])
				require.Equal(t, false, rejectionEntry["payload_included"])
				require.Equal(t, false, rejectionEntry["builder_url_present"])
			}
			require.True(t, capture.HasLog(map[string]any{
				"message":          "ePBS proposal selection completed",
				"slot":             uint64(1),
				"outcome":          "no_valid_proposal",
				"deadline_reached": true,
			}))
		})
	}
}

func TestEPBSProposalSkipsBuilderBidFromUnreadyProvider(t *testing.T) {
	ctx := context.Background()
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"unready": &epbsProposalProvider{proposal: gloasEPBSProposalWithoutPayload(bellatrix.ExecutionAddress{0x01})},
		}),
		first.WithProviderReadiness(&providerReadiness{ready: false}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
}

func TestEPBSProposalAcceptsSelfBuiltProposalFromUnreadyProvider(t *testing.T) {
	ctx := context.Background()
	proposal := gloasEPBSProposal(bellatrix.ExecutionAddress{0x01})
	proposal.GloasContents.Block.Body.SignedExecutionPayloadBid.Message.BuilderIndex = gloas.BuilderIndex(^uint64(0))
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"unready": &epbsProposalProvider{proposal: proposal},
		}),
		first.WithProviderReadiness(&providerReadiness{ready: false}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1})
	require.NoError(t, err)
	require.Same(t, proposal, response.Data)
}

func TestEPBSProposalSkipsProposalWithoutRequestedPayload(t *testing.T) {
	ctx := context.Background()
	includePayload := true
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"excluded": &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}},
		}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{IncludePayload: &includePayload})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
}

func TestEPBSProposalHandlesZeroFeeRecipient(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		mutate func(*gloas.SignedExecutionPayloadBid)
		valid  bool
	}{
		{
			name: "ValidSelfBuild",
			mutate: func(bid *gloas.SignedExecutionPayloadBid) {
				bid.Signature[0] = 0xc0
			},
			valid: true,
		},
		{
			name: "BuilderBacked",
			mutate: func(bid *gloas.SignedExecutionPayloadBid) {
				bid.Message.BuilderIndex = 7
				bid.Signature[0] = 0xc0
			},
		},
		{
			name: "NonZeroValue",
			mutate: func(bid *gloas.SignedExecutionPayloadBid) {
				bid.Message.Value = 1
				bid.Signature[0] = 0xc0
			},
		},
		{
			name: "NonZeroExecutionPayment",
			mutate: func(bid *gloas.SignedExecutionPayloadBid) {
				bid.Message.ExecutionPayment = 1
				bid.Signature[0] = 0xc0
			},
		},
		{
			name:   "NonInfinitySignature",
			mutate: func(*gloas.SignedExecutionPayloadBid) {},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proposal := gloasEPBSProposal(bellatrix.ExecutionAddress{})
			test.mutate(proposal.GloasContents.Block.Body.SignedExecutionPayloadBid)
			service, err := first.New(ctx,
				first.WithLogLevel(zerolog.Disabled),
				first.WithClientMonitor(nullmetrics.New()),
				first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
					"zero-fee": &epbsProposalProvider{proposal: proposal},
				}),
				first.WithTimeout(10*time.Millisecond),
			)
			require.NoError(t, err)

			response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
			if test.valid {
				require.NoError(t, err)
				require.Same(t, proposal, response.Data)
			} else {
				require.Nil(t, response)
				require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
			}
		})
	}
}

func TestEPBSProposalSkipsNilResponse(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.TraceLevel),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"nil": &epbsProposalProvider{nilResponse: true},
		}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
	require.True(t, capture.HasLog(map[string]any{
		"message":          "ePBS proposal provider completed",
		"provider":         "nil",
		"outcome":          "rejected",
		"rejection_reason": "empty_response",
	}))
}

func TestEPBSProposalSkipsMalformedGloasProposal(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		proposal *api.VersionedEPBSProposal
	}{
		{
			name: "Nil",
		},
		{
			name: "GloasWithoutBlock",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
			},
		},
		{
			name: "GloasContentsWithoutBlock",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
				GloasContents:            &apiv1gloas.BlockContents{},
			},
		},
		{
			name: "GloasContentsNil",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
			},
		},
		{
			name: "BlockWithoutBody",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
				Gloas:   &gloas.BeaconBlock{},
			},
		},
		{
			name: "BodyWithoutBid",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
				Gloas: &gloas.BeaconBlock{
					Body: &gloas.BeaconBlockBody{},
				},
			},
		},
		{
			name: "BidWithoutMessage",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
				Gloas: &gloas.BeaconBlock{
					Body: &gloas.BeaconBlockBody{
						SignedExecutionPayloadBid: &gloas.SignedExecutionPayloadBid{},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := first.New(ctx,
				first.WithLogLevel(zerolog.Disabled),
				first.WithClientMonitor(nullmetrics.New()),
				first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
					"malformed": &epbsProposalProvider{proposal: test.proposal},
				}),
				first.WithTimeout(10*time.Millisecond),
			)
			require.NoError(t, err)

			response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
			require.Nil(t, response)
			require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
		})
	}
}

func TestEPBSProposalWaitsForProposalWithRequestedPayload(t *testing.T) {
	ctx := context.Background()
	includePayload := true
	release := make(chan struct{})
	included := &api.VersionedEPBSProposal{ExecutionPayloadIncluded: true}
	time.AfterFunc(20*time.Millisecond, func() {
		close(release)
	})
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"excluded": &epbsProposalProvider{proposal: &api.VersionedEPBSProposal{}},
			"included": &epbsProposalProvider{proposal: included, release: release},
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{IncludePayload: &includePayload})
	require.NoError(t, err)
	require.Same(t, included, response.Data)
}

// gloasEPBSProposal returns a self-built proposal: it carries the payload, which only the
// beacon node's own build can do.
func gloasEPBSProposal(feeRecipient bellatrix.ExecutionAddress) *api.VersionedEPBSProposal {
	return &api.VersionedEPBSProposal{
		Version:                  spec.DataVersionGloas,
		ExecutionPayloadIncluded: true,
		GloasContents: &apiv1gloas.BlockContents{
			Block: &gloas.BeaconBlock{
				Body: &gloas.BeaconBlockBody{
					SignedExecutionPayloadBid: &gloas.SignedExecutionPayloadBid{
						Message: &gloas.ExecutionPayloadBid{
							BuilderIndex: gloas.BuilderIndex(^uint64(0)),
							FeeRecipient: feeRecipient,
						},
					},
				},
			},
		},
	}
}

type providerReadiness struct {
	ready bool
}

func (p *providerReadiness) ProviderReady(string, phase0.Slot, phase0.ValidatorIndex) bool {
	return p.ready
}

type epbsProposalProvider struct {
	proposal            *api.VersionedEPBSProposal
	metadata            map[string]any
	err                 error
	opts                *api.EPBSProposalOpts
	release             <-chan struct{}
	nilResponse         bool
	waitForCancellation bool
}

func (*epbsProposalProvider) Proposal(_ context.Context, _ *api.ProposalOpts) (*api.Response[*api.VersionedProposal], error) {
	return nil, nil
}

func (p *epbsProposalProvider) EPBSProposal(ctx context.Context,
	opts *api.EPBSProposalOpts,
) (
	*api.Response[*api.VersionedEPBSProposal],
	error,
) {
	p.opts = opts
	if p.waitForCancellation {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if p.release != nil {
		<-p.release
	}
	if p.nilResponse {
		return nil, nil
	}
	if p.err != nil {
		return nil, p.err
	}

	return &api.Response[*api.VersionedEPBSProposal]{Data: p.proposal, Metadata: p.metadata}, nil
}

// TestEPBSProposalAcceptsBuilderBackedProposal proves that a proposal the beacon node
// awarded to a P2P builder is a valid result even though Vouch asked for the payload: the
// node never holds a builder's payload, so it cannot return one.
func TestEPBSProposalAcceptsBuilderBackedProposal(t *testing.T) {
	ctx := context.Background()
	includePayload := true
	proposal := gloasEPBSProposalWithoutPayload(bellatrix.ExecutionAddress{0x01})
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"builder": &epbsProposalProvider{proposal: proposal},
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, IncludePayload: &includePayload})
	require.NoError(t, err)
	require.Same(t, proposal, response.Data)
}

// TestEPBSProposalSkipsBuilderBackedProposalWithPayload proves that a builder-backed
// proposal claiming to carry an execution payload is rejected: the two cannot both be true.
func TestEPBSProposalSkipsBuilderBackedProposalWithPayload(t *testing.T) {
	ctx := context.Background()
	includePayload := true
	inconsistent := gloasEPBSProposal(bellatrix.ExecutionAddress{0x01})
	inconsistent.GloasContents.Block.Body.SignedExecutionPayloadBid.Message.BuilderIndex = 7
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"inconsistent": &epbsProposalProvider{proposal: inconsistent},
		}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, IncludePayload: &includePayload})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
}

// gloasEPBSProposalWithoutPayload returns a builder-backed proposal, which carries only
// the block: the winning builder reveals the payload itself.
func gloasEPBSProposalWithoutPayload(feeRecipient bellatrix.ExecutionAddress) *api.VersionedEPBSProposal {
	proposal := gloasEPBSProposal(feeRecipient)
	proposal.Gloas = proposal.GloasContents.Block
	proposal.GloasContents = nil
	proposal.ExecutionPayloadIncluded = false
	proposal.Gloas.Body.SignedExecutionPayloadBid.Message.BuilderIndex = 7

	return proposal
}

// TestEPBSProposalForwardsBuilderConfigUnchanged proves that the strategy passes the
// operator's auction policy to each beacon node as given: the boost is the beacon node's to
// apply, and applying it again here would express a preference nobody configured.
func TestEPBSProposalForwardsBuilderConfigUnchanged(t *testing.T) {
	ctx := context.Background()
	provider := &epbsProposalProvider{proposal: gloasEPBSProposal(bellatrix.ExecutionAddress{0x01})}
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"one": provider,
		}),
		first.WithTimeout(time.Second),
	)
	require.NoError(t, err)

	builderConfig := &gloas.BuilderConfig{
		MinBid:             phase0.Gwei(12345),
		BuilderBoostFactor: 91,
		Builders:           []*gloas.BuilderEntry{},
	}
	_, err = service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, BuilderConfig: builderConfig})
	require.NoError(t, err)

	require.NotNil(t, provider.opts)
	require.Equal(t, builderConfig, provider.opts.BuilderConfig)
}

// TestEPBSProposalSkipsSelfBuiltProposalWithoutPayload proves that a self-built proposal
// that did not carry the requested payload is discarded: only its producing node could
// publish it, so it is unusable here.
func TestEPBSProposalSkipsSelfBuiltProposalWithoutPayload(t *testing.T) {
	ctx := context.Background()
	includePayload := true
	selfBuilt := gloasEPBSProposalWithoutPayload(bellatrix.ExecutionAddress{0x01})
	selfBuilt.Gloas.Body.SignedExecutionPayloadBid.Message.BuilderIndex = gloas.BuilderIndex(^uint64(0))
	service, err := first.New(ctx,
		first.WithLogLevel(zerolog.Disabled),
		first.WithClientMonitor(nullmetrics.New()),
		first.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"self-built": &epbsProposalProvider{proposal: selfBuilt},
		}),
		first.WithTimeout(10*time.Millisecond),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, IncludePayload: &includePayload})
	require.Nil(t, response)
	require.EqualError(t, err, "failed to obtain ePBS beacon block proposal before timeout")
}
