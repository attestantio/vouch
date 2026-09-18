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

package best_test

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1gloas "github.com/attestantio/go-eth2-client/api/v1/gloas"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/beaconblockproposer"
	"github.com/attestantio/vouch/services/cache"
	mockcache "github.com/attestantio/vouch/services/cache/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/strategies/beaconblockproposal/best"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestEPBSProposal(t *testing.T) {
	ctx := context.Background()
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	previousTracerProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(tracerProvider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previousTracerProvider)
		require.NoError(t, tracerProvider.Shutdown(ctx))
	})
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	providerOne := &testEPBSProposalProvider{proposal: testGloasProposal(1, bellatrix.ExecutionAddress{0x01})}
	providerTwo := &testEPBSProposalProvider{proposal: testGloasProposal(1, bellatrix.ExecutionAddress{0x02})}

	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"one": providerOne,
			"two": providerTwo,
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	builderConfig := &gloas.BuilderConfig{MinBid: 12, BuilderBoostFactor: 100, Builders: []*gloas.BuilderEntry{}}
	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot:          phase0.Slot(1),
		BuilderConfig: builderConfig,
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.NotNil(t, response.Data)
	require.Same(t, builderConfig, providerOne.opts.BuilderConfig)
	require.Same(t, builderConfig, providerTwo.opts.BuilderConfig)

	var epbsProposalSpan sdktrace.ReadOnlySpan
	providerSpans := make(map[string]sdktrace.ReadOnlySpan)
	for _, span := range spanRecorder.Ended() {
		switch span.Name() {
		case "EPBSProposal":
			epbsProposalSpan = span
		case "ePBSBeaconBlockProposal":
			for _, attribute := range span.Attributes() {
				if string(attribute.Key) == "provider" {
					providerSpans[attribute.Value.AsString()] = span
				}
			}
		}
	}
	require.NotNil(t, epbsProposalSpan)
	for _, provider := range []string{"one", "two"} {
		span, exists := providerSpans[provider]
		require.True(t, exists, "provider %q should create a span", provider)
		require.Equal(t, epbsProposalSpan.SpanContext(), span.Parent())
	}
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

	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	proposal := testGloasProposalWithoutPayload(1, bellatrix.ExecutionAddress{0x01})
	proposal.ExecutionValue = big.NewInt(123)
	bodyRoot := phase0.Root{0x42}
	proposal.BeaconBlockBodyRoot = &bodyRoot

	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.TraceLevel),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"stable-provider": &testEPBSProposalProvider{
				proposal: proposal,
				metadata: map[string]any{"Eth-Builder-Url": "https://builder.example"},
			},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	includePayload := true
	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{
		Slot:           1,
		IncludePayload: &includePayload,
		BuilderConfig: &gloas.BuilderConfig{
			MinBid:             11,
			BuilderBoostFactor: 100,
		},
	})
	require.NoError(t, err)
	require.Equal(t, "best", response.Metadata["vouch.strategy"])
	require.Equal(t, "stable-provider", response.Metadata["vouch.provider"])
	require.Equal(t, "builder_api", response.Metadata["vouch.source"])
	require.True(t, capture.HasLog(map[string]any{
		"message":             "ePBS proposal provider completed",
		"slot":                uint64(1),
		"provider":            "stable-provider",
		"source":              "builder_api",
		"builder_index":       uint64(7),
		"value_known":         true,
		"execution_value":     "123",
		"payload_included":    false,
		"builder_url_present": true,
		"outcome":             "accepted",
		"rejection_reason":    "",
	}))
	require.Equal(t, false, response.Metadata["vouch.fallback"])

	var requestID string
	for _, recordedSpan := range spanRecorder.Ended() {
		attributes := make(map[string]any)
		for _, attr := range recordedSpan.Attributes() {
			attributes[string(attr.Key)] = attr.Value.AsInterface()
		}
		if recordedSpan.Name() == "EPBSProposal" {
			requestID, _ = attributes["request_id"].(string)
			require.Equal(t, int64(1), attributes["slot"])
			require.Equal(t, "stable-provider", attributes["provider"])
			require.Equal(t, "builder_api", attributes["source"])
			require.NotEmpty(t, attributes["proposal_root"])
		}
		if recordedSpan.Name() == "ePBSBeaconBlockProposal" {
			require.Equal(t, int64(1), attributes["slot"])
			require.Equal(t, "stable-provider", attributes["provider"])
			require.Equal(t, "builder_api", attributes["source"])
			require.Equal(t, true, attributes["value_known"])
			require.Equal(t, "123", attributes["execution_value"])
			require.Equal(t, "124", attributes["score"])
			require.NotEmpty(t, attributes["proposal_root"])
		}
	}
	require.NotEmpty(t, requestID)
}

func TestEPBSProposalMasksProviderAddress(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	const providerAddress = "https://user:secret@example.com/path?token=secret"
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.TraceLevel),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			providerAddress: &testEPBSProposalProvider{proposal: &api.VersionedEPBSProposal{}},
			"https://user:othersecret@example.com/path?token=othersecret": &testEPBSProposalProvider{
				err: errors.New("request to https://user:othersecret@example.com/path?token=othersecret failed"),
			},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.NoError(t, err)
	providerName, ok := response.Metadata["vouch.provider"].(string)
	require.True(t, ok)
	require.NotEqual(t, providerAddress, providerName)
	require.NotContains(t, providerName, "secret")
	for _, entry := range capture.Entries() {
		provider, _ := entry["provider"].(string)
		require.NotContains(t, provider, "secret")
		errorText, _ := entry["error"].(string)
		require.NotContains(t, errorText, "secret")
	}
}

func TestEPBSProposalRejectsBuilderBidFromUnreadyProvider(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"unready": &testEPBSProposalProvider{proposal: testGloasProposalWithoutPayload(1, bellatrix.ExecutionAddress{0x01})},
		}),
		best.WithProviderReadiness(&providerReadiness{ready: false}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1})
	require.Nil(t, response)
	require.EqualError(t, err, "no ePBS proposals received")
}

func TestEPBSProposalLogsProviderRejection(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	proposal := testGloasProposalWithoutPayload(1, bellatrix.ExecutionAddress{0x01})

	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.TraceLevel),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"unready": &testEPBSProposalProvider{proposal: proposal},
		}),
		best.WithProviderReadiness(&providerReadiness{ready: false}),
		best.WithTimeout(10*time.Millisecond),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1})
	require.Nil(t, response)
	require.EqualError(t, err, "no ePBS proposals received")
	require.True(t, capture.HasLog(map[string]any{
		"message":          "ePBS proposal provider completed",
		"provider":         "unready",
		"outcome":          "rejected",
		"rejection_reason": "provider_preferences_not_ready",
	}))
}

func TestEPBSProposalLogsProviderError(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.TraceLevel),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"failed-provider": &testEPBSProposalProvider{err: errors.New("connection failed")},
		}),
		best.WithTimeout(10*time.Millisecond),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1})
	require.Nil(t, response)
	require.EqualError(t, err, "no ePBS proposals received")
	require.True(t, capture.HasLog(map[string]any{
		"message":             "ePBS proposal provider completed",
		"slot":                uint64(1),
		"provider":            "failed-provider",
		"source":              "unknown",
		"builder_index":       "unknown",
		"value_known":         false,
		"execution_value":     "unknown",
		"payload_included":    false,
		"builder_url_present": false,
		"outcome":             "error",
		"rejection_reason":    "provider_error",
	}))
	require.True(t, capture.HasLog(map[string]any{
		"message":               "ePBS proposal selection completed",
		"slot":                  uint64(1),
		"outcome":               "no_valid_proposal",
		"responded":             0,
		"errored":               1,
		"timed_out":             0,
		"soft_deadline_reached": false,
		"hard_deadline_reached": false,
	}))
}

func TestEPBSProposalLogsProviderTimeout(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.TraceLevel),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"slow-provider":     &testEPBSProposalProvider{waitForCancellation: true},
			"deadline-provider": &testEPBSProposalProvider{err: context.DeadlineExceeded},
		}),
		best.WithTimeout(20*time.Millisecond),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1})
	require.Nil(t, response)
	require.EqualError(t, err, "no ePBS proposals received")
	require.True(t, capture.HasLog(map[string]any{
		"message":          "ePBS proposal provider completed",
		"provider":         "slow-provider",
		"outcome":          "timeout",
		"rejection_reason": "deadline_reached",
	}))
	require.True(t, capture.HasLog(map[string]any{
		"message":          "ePBS proposal provider completed",
		"provider":         "deadline-provider",
		"outcome":          "timeout",
		"rejection_reason": "deadline_reached",
	}))
	require.True(t, capture.HasLog(map[string]any{
		"message":          "ePBS proposal selection completed",
		"slot":             uint64(1),
		"outcome":          "timeout",
		"deadline_reached": true,
	}))
}

func TestEPBSProposalReturnsIncludedCandidateAtSoftTimeout(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	includePayload := true
	candidate := &api.VersionedEPBSProposal{ExecutionPayloadIncluded: true}
	const timeout = 200 * time.Millisecond
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.TraceLevel),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"included": &testEPBSProposalProvider{proposal: candidate},
			"error":    &testEPBSProposalProvider{err: errors.New("failed")},
			"slow":     &testEPBSProposalProvider{waitForCancellation: true},
		}),
		best.WithTimeout(timeout),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	started := time.Now()
	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{IncludePayload: &includePayload})
	elapsed := time.Since(started)
	require.NoError(t, err)
	require.Same(t, candidate, response.Data)
	require.Less(t, elapsed, 3*timeout/4)
	require.True(t, capture.HasLog(map[string]any{
		"message":          "ePBS proposal provider completed",
		"provider":         "slow",
		"outcome":          "timeout",
		"rejection_reason": "soft_deadline_reached",
	}))
	require.Equal(t, true, response.Metadata["vouch.fallback"])
}

func TestEPBSProposalPrefersIncludedCandidate(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	includePayload := true
	includedCandidate := &api.VersionedEPBSProposal{
		ExecutionPayloadIncluded: true,
		ConsensusValue:           big.NewInt(1),
	}
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"included": &testEPBSProposalProvider{proposal: includedCandidate},
			"external": &testEPBSProposalProvider{proposal: &api.VersionedEPBSProposal{
				ConsensusValue: big.NewInt(100),
			}},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{IncludePayload: &includePayload})
	require.NoError(t, err)
	require.Same(t, includedCandidate, response.Data)
}

func TestEPBSProposalHandlesZeroFeeRecipient(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
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
			cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
			zeroFeeCandidate := testGloasProposal(100, bellatrix.ExecutionAddress{})
			zeroFeeCandidate.ExecutionValue = big.NewInt(0)
			test.mutate(zeroFeeCandidate.GloasContents.Block.Body.SignedExecutionPayloadBid)
			validCandidate := testGloasProposal(1, bellatrix.ExecutionAddress{0x01})
			validCandidate.ExecutionValue = big.NewInt(0)
			service, err := best.New(ctx,
				best.WithLogLevel(zerolog.Disabled),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithProcessConcurrency(2),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
					"zero-fee": &testEPBSProposalProvider{proposal: zeroFeeCandidate},
					"valid":    &testEPBSProposalProvider{proposal: validCandidate},
				}),
				best.WithTimeout(time.Second),
				best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
			)
			require.NoError(t, err)

			response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
			require.NoError(t, err)
			if test.valid {
				require.Same(t, zeroFeeCandidate, response.Data)
			} else {
				require.Same(t, validCandidate, response.Data)
			}
		})
	}
}

func TestEPBSProposalRejectsZeroFeeRecipientWithoutPayload(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	zeroFeeCandidate := testGloasProposalWithoutPayload(100, bellatrix.ExecutionAddress{})
	validCandidate := testGloasProposalWithoutPayload(1, bellatrix.ExecutionAddress{0x01})
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(2),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"zero-fee": &testEPBSProposalProvider{proposal: zeroFeeCandidate},
			"valid":    &testEPBSProposalProvider{proposal: validCandidate},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.NoError(t, err)
	require.Same(t, validCandidate, response.Data)
}

func TestEPBSProposalDoesNotWeightExecutionPayloadGas(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	consensusCandidate := testGloasProposal(2, bellatrix.ExecutionAddress{0x01})
	consensusCandidate.ExecutionValue = big.NewInt(2)
	executionCandidate := testGloasProposal(0, bellatrix.ExecutionAddress{0x02})
	executionCandidate.ConsensusValue = nil
	executionCandidate.ExecutionValue = big.NewInt(0)
	executionCandidate.GloasContents.ExecutionPayloadEnvelope = &gloas.ExecutionPayloadEnvelope{
		Payload: &gloas.ExecutionPayload{GasUsed: 3},
	}
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.WarnLevel),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(2),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"consensus": &testEPBSProposalProvider{proposal: consensusCandidate},
			"execution": &testEPBSProposalProvider{proposal: executionCandidate},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
		best.WithExecutionPayloadFactor(1),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.NoError(t, err)
	require.Same(t, consensusCandidate, response.Data)
}

func TestEPBSProposalComparesLargeValuesExactly(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	base := new(big.Int).Lsh(big.NewInt(1), 54)
	lowerValueCandidate := testGloasProposal(0, bellatrix.ExecutionAddress{0x01})
	lowerValueCandidate.ExecutionValue = new(big.Int).Add(base, big.NewInt(1))
	higherValueCandidate := testGloasProposal(0, bellatrix.ExecutionAddress{0x02})
	higherValueCandidate.ExecutionValue = new(big.Int).Add(base, big.NewInt(2))
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(2),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"lower":  &testEPBSProposalProvider{proposal: lowerValueCandidate},
			"higher": &testEPBSProposalProvider{proposal: higherValueCandidate, delay: 10 * time.Millisecond},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
	require.NoError(t, err)
	require.Same(t, higherValueCandidate, response.Data)
}

func TestEPBSProposalRejectsNilData(t *testing.T) {
	ctx := context.Background()
	capture := logger.NewLogCapture()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	validCandidate := testGloasProposal(1, bellatrix.ExecutionAddress{0x01})
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.TraceLevel),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(2),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"nil":   &testEPBSProposalProvider{},
			"valid": &testEPBSProposalProvider{proposal: validCandidate},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	includePayload := true
	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{IncludePayload: &includePayload})
	require.NoError(t, err)
	require.Same(t, validCandidate, response.Data)
	require.True(t, capture.HasLog(map[string]any{
		"message":          "ePBS proposal provider completed",
		"provider":         "nil",
		"outcome":          "rejected",
		"rejection_reason": "empty_response",
	}))
}

func TestEPBSProposalRejectsMalformedIncludedGloasProposal(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	tests := []struct {
		name     string
		proposal *api.VersionedEPBSProposal
	}{
		{
			name: "MissingGloasContents",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
			},
		},
		{
			name: "MissingBlock",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
				GloasContents:            &apiv1gloas.BlockContents{},
			},
		},
		{
			name: "MissingBody",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
				GloasContents:            &apiv1gloas.BlockContents{Block: &gloas.BeaconBlock{}},
			},
		},
		{
			name: "MissingSignedExecutionPayloadBid",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
				GloasContents: &apiv1gloas.BlockContents{Block: &gloas.BeaconBlock{
					Body: &gloas.BeaconBlockBody{},
				}},
			},
		},
		{
			name: "MissingExecutionPayloadBidMessage",
			proposal: &api.VersionedEPBSProposal{
				Version:                  spec.DataVersionGloas,
				ExecutionPayloadIncluded: true,
				GloasContents: &apiv1gloas.BlockContents{Block: &gloas.BeaconBlock{
					Body: &gloas.BeaconBlockBody{
						SignedExecutionPayloadBid: &gloas.SignedExecutionPayloadBid{},
					},
				}},
			},
		},
		{
			name: "CachedMissingBlock",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
			},
		},
		{
			name: "CachedMissingBody",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
				Gloas:   &gloas.BeaconBlock{},
			},
		},
		{
			name: "CachedMissingSignedExecutionPayloadBid",
			proposal: &api.VersionedEPBSProposal{
				Version: spec.DataVersionGloas,
				Gloas: &gloas.BeaconBlock{
					Body: &gloas.BeaconBlockBody{},
				},
			},
		},
		{
			name: "CachedMissingExecutionPayloadBidMessage",
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
			validCandidate := testGloasProposal(1, bellatrix.ExecutionAddress{0x01})
			service, err := best.New(ctx,
				best.WithLogLevel(zerolog.Disabled),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithProcessConcurrency(2),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
					"malformed": &testEPBSProposalProvider{proposal: test.proposal},
					"valid":     &testEPBSProposalProvider{proposal: validCandidate},
				}),
				best.WithTimeout(time.Second),
				best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
			)
			require.NoError(t, err)

			response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{})
			require.NoError(t, err)
			require.Same(t, validCandidate, response.Data)
		})
	}
}

// testGloasProposal returns a self-built proposal: it carries the payload, which only the
// beacon node's own build can do.
func testGloasProposal(value int64, feeRecipient bellatrix.ExecutionAddress) *api.VersionedEPBSProposal {
	return &api.VersionedEPBSProposal{
		Version:                  spec.DataVersionGloas,
		ExecutionPayloadIncluded: true,
		ConsensusValue:           big.NewInt(value),
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

// testGloasProposalWithoutPayload returns a builder-backed proposal, which carries only the
// block: the winning builder reveals the payload itself.
func testGloasProposalWithoutPayload(value int64, feeRecipient bellatrix.ExecutionAddress) *api.VersionedEPBSProposal {
	proposal := testGloasProposal(value, feeRecipient)
	proposal.Gloas = proposal.GloasContents.Block
	proposal.GloasContents = nil
	proposal.ExecutionPayloadIncluded = false
	proposal.Gloas.Body.SignedExecutionPayloadBid.Message.BuilderIndex = 7

	return proposal
}

func TestEPBSProposalExpandsClientGraffitiPerProvider(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	firstProvider := &clientGraffitiEPBSProposalProvider{
		client:   "first",
		graffiti: make(chan [32]byte, 1),
	}
	const longClient = "second-client-version-with-more-than-thirty-two-bytes"
	secondProvider := &clientGraffitiEPBSProposalProvider{
		client:   longClient,
		graffiti: make(chan [32]byte, 1),
	}
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(2),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"first":  firstProvider,
			"second": secondProvider,
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)
	var graffiti [32]byte
	copy(graffiti[:], "{{CLIENT}}")

	_, err = service.EPBSProposal(ctx, &api.EPBSProposalOpts{Graffiti: graffiti})
	require.NoError(t, err)
	var expectedFirst [32]byte
	copy(expectedFirst[:], "first")
	require.Equal(t, expectedFirst, <-firstProvider.graffiti)
	var expectedSecond [32]byte
	copy(expectedSecond[:], longClient)
	require.Equal(t, expectedSecond, <-secondProvider.graffiti)
}

func TestEPBSProposalPreservesGraffitiWhenClientLookupFails(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	provider := &clientGraffitiEPBSProposalProvider{
		nodeClientErr: errors.New("node client unavailable"),
		graffiti:      make(chan [32]byte, 1),
	}
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"provider": provider,
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	var graffiti [32]byte
	copy(graffiti[:], "configured {{CLIENT}}")
	_, err = service.EPBSProposal(ctx, &api.EPBSProposalOpts{Graffiti: graffiti})
	require.NoError(t, err)
	require.Equal(t, graffiti, <-provider.graffiti)
}

func TestEPBSProposalStartsProvidersWhileGraffitiClientLookupIsSlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	slowProvider := &slowClientGraffitiEPBSProposalProvider{
		nodeClientStarted: make(chan struct{}),
		release:           make(chan struct{}),
	}
	releaseSlowProvider := slowProvider.release
	t.Cleanup(func() {
		select {
		case <-releaseSlowProvider:
		default:
			close(releaseSlowProvider)
		}
	})
	healthyProvider := &waitingClientGraffitiEPBSProposalProvider{
		waitFor:         slowProvider.nodeClientStarted,
		proposalStarted: make(chan struct{}),
	}
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(2),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"slow":    slowProvider,
			"healthy": healthyProvider,
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)
	var graffiti [32]byte
	copy(graffiti[:], "{{CLIENT}}")

	errCh := make(chan error, 1)
	go func() {
		_, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Graffiti: graffiti})
		errCh <- err
	}()

	select {
	case <-slowProvider.nodeClientStarted:
	case <-time.After(200 * time.Millisecond):
		require.Fail(t, "slow provider client lookup did not start")
	}
	select {
	case <-healthyProvider.proposalStarted:
	case <-time.After(200 * time.Millisecond):
		require.Fail(t, "healthy provider proposal did not start promptly")
	}
	close(releaseSlowProvider)
	require.NoError(t, <-errCh)
}

type providerReadiness struct {
	ready bool
}

func (p *providerReadiness) ProviderReady(string, phase0.Slot, phase0.ValidatorIndex) bool {
	return p.ready
}

type testEPBSProposalProvider struct {
	proposal            *api.VersionedEPBSProposal
	metadata            map[string]any
	opts                *api.EPBSProposalOpts
	err                 error
	delay               time.Duration
	waitForCancellation bool
}

type clientGraffitiEPBSProposalProvider struct {
	client        string
	nodeClientErr error
	graffiti      chan [32]byte
}

func (p *clientGraffitiEPBSProposalProvider) Proposal(ctx context.Context,
	opts *api.ProposalOpts,
) (*api.Response[*api.VersionedProposal], error) {
	p.graffiti <- opts.Graffiti

	return mock.NewProposalProvider().Proposal(ctx, opts)
}

func (p *clientGraffitiEPBSProposalProvider) EPBSProposal(
	_ context.Context,
	opts *api.EPBSProposalOpts,
) (*api.Response[*api.VersionedEPBSProposal], error) {
	p.graffiti <- opts.Graffiti
	return &api.Response[*api.VersionedEPBSProposal]{Data: &api.VersionedEPBSProposal{}}, nil
}

func (p *clientGraffitiEPBSProposalProvider) NodeClient(
	_ context.Context,
) (*api.Response[string], error) {
	if p.nodeClientErr != nil {
		return nil, p.nodeClientErr
	}
	return &api.Response[string]{Data: p.client}, nil
}

var _ eth2client.NodeClientProvider = (*clientGraffitiEPBSProposalProvider)(nil)

type slowClientGraffitiEPBSProposalProvider struct {
	nodeClientStarted chan struct{}
	release           chan struct{}
	startOnce         sync.Once
}

func (*slowClientGraffitiEPBSProposalProvider) Proposal(
	_ context.Context,
	_ *api.ProposalOpts,
) (*api.Response[*api.VersionedProposal], error) {
	return nil, nil
}

func (*slowClientGraffitiEPBSProposalProvider) EPBSProposal(
	_ context.Context,
	_ *api.EPBSProposalOpts,
) (*api.Response[*api.VersionedEPBSProposal], error) {
	return &api.Response[*api.VersionedEPBSProposal]{Data: &api.VersionedEPBSProposal{}}, nil
}

func (p *slowClientGraffitiEPBSProposalProvider) NodeClient(
	ctx context.Context,
) (*api.Response[string], error) {
	p.startOnce.Do(func() {
		close(p.nodeClientStarted)
	})
	select {
	case <-p.release:
		return &api.Response[string]{Data: "slow"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var _ eth2client.NodeClientProvider = (*slowClientGraffitiEPBSProposalProvider)(nil)

type waitingClientGraffitiEPBSProposalProvider struct {
	waitFor         <-chan struct{}
	proposalStarted chan struct{}
	proposalOnce    sync.Once
}

func (*waitingClientGraffitiEPBSProposalProvider) Proposal(
	_ context.Context,
	_ *api.ProposalOpts,
) (*api.Response[*api.VersionedProposal], error) {
	return nil, nil
}

func (p *waitingClientGraffitiEPBSProposalProvider) EPBSProposal(
	_ context.Context,
	_ *api.EPBSProposalOpts,
) (*api.Response[*api.VersionedEPBSProposal], error) {
	p.proposalOnce.Do(func() {
		close(p.proposalStarted)
	})
	return &api.Response[*api.VersionedEPBSProposal]{Data: &api.VersionedEPBSProposal{}}, nil
}

func (p *waitingClientGraffitiEPBSProposalProvider) NodeClient(
	ctx context.Context,
) (*api.Response[string], error) {
	select {
	case <-p.waitFor:
		return &api.Response[string]{Data: "healthy"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var _ eth2client.NodeClientProvider = (*waitingClientGraffitiEPBSProposalProvider)(nil)

func (*testEPBSProposalProvider) Proposal(_ context.Context, _ *api.ProposalOpts) (*api.Response[*api.VersionedProposal], error) {
	return nil, nil
}

func (p *testEPBSProposalProvider) EPBSProposal(ctx context.Context,
	opts *api.EPBSProposalOpts,
) (
	*api.Response[*api.VersionedEPBSProposal],
	error,
) {
	p.opts = opts
	if p.delay != 0 {
		time.Sleep(p.delay)
	}
	if p.waitForCancellation {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if p.err != nil {
		return nil, p.err
	}

	return &api.Response[*api.VersionedEPBSProposal]{Data: p.proposal, Metadata: p.metadata}, nil
}

// TestEPBSProposalRecordsDegradedSelectionWithUnknownValues proves that when no valid
// response reports a value, the strategy still selects one but records that the selection
// was made without value information.  A selection known to be economically blind is worth
// distinguishing from a normal one.
func TestEPBSProposalRecordsDegradedSelectionWithUnknownValues(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})

	tests := []struct {
		name     string
		value    *big.Int
		degraded bool
	}{
		{
			name:     "AllUnknown",
			degraded: true,
		},
		{
			name:  "KnownValue",
			value: big.NewInt(2),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proposal := testGloasProposal(1, bellatrix.ExecutionAddress{0x01})
			proposal.ExecutionValue = test.value
			service, err := best.New(ctx,
				best.WithLogLevel(zerolog.Disabled),
				best.WithClientMonitor(nullmetrics.New()),
				best.WithProcessConcurrency(1),
				best.WithChainTimeService(chainTime),
				best.WithSpecProvider(specProvider),
				best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
					"one": &testEPBSProposalProvider{proposal: proposal},
				}),
				best.WithTimeout(time.Second),
				best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
			)
			require.NoError(t, err)

			response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1})
			require.NoError(t, err)
			require.Same(t, proposal, response.Data)
			require.Equal(t, test.degraded, response.Metadata["vouch.fallback"])
		})
	}
}

// TestEPBSProposalAcceptsBuilderBackedProposal proves that a proposal the beacon node
// awarded to a P2P builder is a valid candidate even though Vouch asked for the payload:
// the node never holds a builder's payload, so it cannot return one.
func TestEPBSProposalAcceptsBuilderBackedProposal(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	proposal := testGloasProposalWithoutPayload(1, bellatrix.ExecutionAddress{0x01})
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"builder": &testEPBSProposalProvider{proposal: proposal},
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	includePayload := true
	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, IncludePayload: &includePayload})
	require.NoError(t, err)
	require.Same(t, proposal, response.Data)
}

// TestEPBSProposalRejectsBuilderBackedProposalWithPayload proves that a builder-backed
// proposal claiming to carry an execution payload is discarded: the two cannot both be true.
func TestEPBSProposalRejectsBuilderBackedProposalWithPayload(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	inconsistent := testGloasProposal(1, bellatrix.ExecutionAddress{0x01})
	inconsistent.GloasContents.Block.Body.SignedExecutionPayloadBid.Message.BuilderIndex = 7
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"inconsistent": &testEPBSProposalProvider{proposal: inconsistent},
		}),
		best.WithTimeout(100*time.Millisecond),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	includePayload := true
	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, IncludePayload: &includePayload})
	require.Nil(t, response)
	require.EqualError(t, err, "no ePBS proposals received")
}

// TestEPBSProposalForwardsBuilderConfigUnchanged proves that the strategy passes the
// operator's auction policy to each beacon node as given: the boost is the beacon node's to
// apply, and applying it again here would express a preference nobody configured.
func TestEPBSProposalForwardsBuilderConfigUnchanged(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	provider := &testEPBSProposalProvider{proposal: testGloasProposal(1, bellatrix.ExecutionAddress{0x01})}
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"one": provider,
		}),
		best.WithTimeout(time.Second),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
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

// TestEPBSProposalRejectsSelfBuiltProposalWithoutPayload proves that a self-built proposal
// that did not carry the requested payload is discarded: only its producing node could
// publish it, so it is unusable here.
func TestEPBSProposalRejectsSelfBuiltProposalWithoutPayload(t *testing.T) {
	ctx := context.Background()
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(time.Now())),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)
	cacheSvc := mockcache.New(map[phase0.Root]phase0.Slot{})
	selfBuilt := testGloasProposalWithoutPayload(1, bellatrix.ExecutionAddress{0x01})
	selfBuilt.Gloas.Body.SignedExecutionPayloadBid.Message.BuilderIndex = gloas.BuilderIndex(^uint64(0))
	service, err := best.New(ctx,
		best.WithLogLevel(zerolog.Disabled),
		best.WithClientMonitor(nullmetrics.New()),
		best.WithProcessConcurrency(1),
		best.WithChainTimeService(chainTime),
		best.WithSpecProvider(specProvider),
		best.WithProposalProviders(map[string]beaconblockproposer.ProposalDataProvider{
			"self-built": &testEPBSProposalProvider{proposal: selfBuilt},
		}),
		best.WithTimeout(100*time.Millisecond),
		best.WithBlockRootToSlotCache(cacheSvc.(cache.BlockRootToSlotProvider)),
	)
	require.NoError(t, err)

	includePayload := true
	response, err := service.EPBSProposal(ctx, &api.EPBSProposalOpts{Slot: 1, IncludePayload: &includePayload})
	require.Nil(t, response)
	require.EqualError(t, err, "no ePBS proposals received")
}
