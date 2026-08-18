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

package standard_test

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/signer/standard"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type minimalSpecProvider struct{}

func (*minimalSpecProvider) Spec(_ context.Context, _ *api.SpecOpts) (*api.Response[map[string]any], error) {
	return &api.Response[map[string]any]{
		Data: map[string]any{
			"SLOTS_PER_EPOCH":            uint64(32),
			"DOMAIN_BEACON_ATTESTER":     phase0.DomainType{0x01},
			"DOMAIN_BEACON_PROPOSER":     phase0.DomainType{0x02},
			"DOMAIN_RANDAO":              phase0.DomainType{0x03},
			"DOMAIN_SELECTION_PROOF":     phase0.DomainType{0x04},
			"DOMAIN_AGGREGATE_AND_PROOF": phase0.DomainType{0x05},
		},
	}, nil
}

func TestService(t *testing.T) {
	specProvider := mock.NewSpecProvider()
	domainProvider := mock.NewDomainProvider()

	tests := []struct {
		name     string
		params   []standard.Parameter
		err      string
		logEntry string
	}{
		{
			name: "MonitorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nil),
				standard.WithClientMonitor(nullmetrics.New()),
				standard.WithSpecProvider(specProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ClientMonitorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithClientMonitor(nil),
				standard.WithSpecProvider(specProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "SpecProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithClientMonitor(nullmetrics.New()),
				standard.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no spec provider specified",
		},
		{
			name: "SpecProviderErrors",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithClientMonitor(nullmetrics.New()),
				standard.WithSpecProvider(mock.NewErroringSpecProvider()),
				standard.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain spec: error",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New()),
				standard.WithClientMonitor(nullmetrics.New()),
				standard.WithSpecProvider(specProvider),
				standard.WithDomainProvider(domainProvider),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			_, err := standard.New(context.Background(), test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				if test.logEntry != "" {
					capture.AssertHasEntry(t, test.logEntry)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestServiceWithOptionalDomainsAbsent(t *testing.T) {
	service, err := standard.New(context.Background(),
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithClientMonitor(nullmetrics.New()),
		standard.WithSpecProvider(&minimalSpecProvider{}),
		standard.WithDomainProvider(mock.NewDomainProvider()),
	)
	require.NoError(t, err)
	require.NotNil(t, service)
}
