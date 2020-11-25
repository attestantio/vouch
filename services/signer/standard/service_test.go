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

	"github.com/attestantio/vouch/mock"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/services/signer/standard"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	slotsPerEpochProvider := mock.NewSlotsPerEpochProvider(32)
	beaconProposerDomainTypeProvider := mock.NewBeaconProposerDomainProvider()
	beaconAttesterDomainTypeProvider := mock.NewBeaconAttesterDomainProvider()
	randaoDomainTypeProvider := mock.NewRANDAODomainProvider()
	selectionProofDomainTypeProvider := mock.NewSelectionProofDomainProvider()
	aggregateAndProofDomainTypeProvider := mock.NewAggregateAndProofDomainProvider()
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
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ClientMonitorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nil),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "SlotsPerEpochProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no slots per epoch provider specified",
		},
		{
			name: "SlotsPerEpochProviderErrors",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(mock.NewErroringSlotsPerEpochProvider()),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain slots per epoch: error",
		},
		{
			name: "BeaonProposerDomainTypeProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no beacon proposer domain type provider specified",
		},
		{
			name: "BeaonProposerDomainTypeProviderErrors",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(mock.NewErroringBeaconProposerDomainProvider()),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain beacon proposer domain type: error",
		},
		{
			name: "BeaonAttesterDomainTypeMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no beacon attester domain type provider specified",
		},
		{
			name: "BeaonAttesterDomainTypeErrors",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(mock.NewErroringBeaconAttesterDomainProvider()),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain beacon attester domain type: error",
		},
		{
			name: "RANDAODomainTypeProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no RANDAO domain type provider specified",
		},
		{
			name: "RANDAODomainTypeProviderErrors",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(mock.NewErroringRANDAODomainProvider()),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain RANDAO domain type: error",
		},
		{
			name: "SelectionProofDomianTypeProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no selection proof domain type provider specified",
		},
		{
			name: "SelectionProofDomianTypeProviderErrors",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(mock.NewErroringSelectionProofDomainProvider()),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain selection proof domain type: error",
		},
		{
			name: "AggregateAndProofDomianTypeProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no aggregate and proof domain type provider specified",
		},
		{
			name: "AggregateAndProofDomianTypeProviderErrors",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(mock.NewErroringAggregateAndProofDomainProvider()),
				standard.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain aggregate and proof domain type: error",
		},
		{
			name: "DomainProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
			},
			err: "problem with parameters: no domain provider specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(context.Background())),
				standard.WithClientMonitor(nullmetrics.New(context.Background())),
				standard.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				standard.WithBeaconProposerDomainTypeProvider(beaconProposerDomainTypeProvider),
				standard.WithBeaconAttesterDomainTypeProvider(beaconAttesterDomainTypeProvider),
				standard.WithRANDAODomainTypeProvider(randaoDomainTypeProvider),
				standard.WithSelectionProofDomainTypeProvider(selectionProofDomainTypeProvider),
				standard.WithAggregateAndProofDomainTypeProvider(aggregateAndProofDomainTypeProvider),
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
