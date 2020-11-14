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

package dirk_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/attestantio/dirk/testing/daemon"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/accountmanager/dirk"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/attestantio/vouch/testing/resources"
	"github.com/attestantio/vouch/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func _byte(input string) []byte {
	res, _ := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	return res
}

func _root(input string) spec.Root {
	res, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		panic(err)
	}
	var root spec.Root
	copy(root[:], res)
	return root
}

func _sig(input string) spec.BLSSignature {
	res, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		panic(err)
	}
	var sig spec.BLSSignature
	copy(sig[:], res)
	return sig
}

func _pubKey(input string) spec.BLSPubKey {
	res, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		panic(err)
	}
	var pubKey spec.BLSPubKey
	copy(pubKey[:], res)
	return pubKey
}

func TestService(t *testing.T) {
	slotsPerEpochProvider := mock.NewSlotsPerEpochProvider(32)
	beaconProposerDomainProvider := mock.NewBeaconProposerDomainProvider()
	beaconAttesterDomainProvider := mock.NewBeaconAttesterDomainProvider()
	randaoDomainProvider := mock.NewRANDAODomainProvider()
	selectionProofDomainProvider := mock.NewSelectionProofDomainProvider()
	aggregateAndProofDomainProvider := mock.NewAggregateAndProofDomainProvider()
	domainProvider := mock.NewDomainProvider()
	validatorsProvider := mock.NewValidatorsProvider()

	tests := []struct {
		name     string
		params   []dirk.Parameter
		err      string
		logEntry string
	}{
		{
			name: "MonitorNil",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nil),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ClientMonitorNil",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nil),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "EndpointsNil",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no endpoints specified",
		},
		{
			name: "EndpointsEmpty",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no endpoints specified",
		},
		{
			name: "EndpointsMalformedEndpoint",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{""}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err:      "no valid endpoints specified",
			logEntry: "Malformed endpoint",
		},
		{
			name: "EndpointsMalformedPort",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"host:bad"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err:      "no valid endpoints specified",
			logEntry: "Malformed port",
		},
		{
			name: "EndpointsInvalidPort",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"host:0"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err:      "no valid endpoints specified",
			logEntry: "Invalid port",
		},
		{
			name: "AccountPathsNil",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no account paths specified",
		},
		{
			name: "AccountPathsEmpty",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no account paths specified",
		},
		{
			name: "ClientCertMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no client certificate specified",
		},
		{
			name: "ClientKeyMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no client key specified",
		},
		{
			name: "ClientCertKeyMismatch",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.Disabled),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest02Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "failed to build credentials: failed to load client keypair: tls: private key does not match public key",
		},
		{
			name: "ValidatorsProviderMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no validators provider specified",
		},
		{
			name: "SlotsPerEpochProviderMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no slots per epoch provider specified",
		},
		{
			name: "SlotsPerEpochProviderErrors",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.Disabled),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(mock.NewErroringSlotsPerEpochProvider()),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain slots per epoch: error",
		},
		{
			name: "BeaconProposerDomainProviderMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no beacon proposer domain provider specified",
		},
		{
			name: "BeaconProposerDomainProviderErrors",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(mock.NewErroringBeaconProposerDomainProvider()),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain beacon proposer domain: error",
		},
		{
			name: "BeaconAttesterDomainProviderMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no beacon attester domain provider specified",
		},
		{
			name: "BeaconAttesterDomainProviderErrors",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(mock.NewErroringBeaconAttesterDomainProvider()),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain beacon attester domain: error",
		},
		{
			name: "RANDAODomainProviderMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no RANDAO domain provider specified",
		},
		{
			name: "RANDAODomainProviderErrors",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(mock.NewErroringRANDAODomainProvider()),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain RANDAO domain: error",
		},
		{
			name: "SelectionProofDomainProviderMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no selection proof domain provider specified",
		},
		{
			name: "SelectionProofDomainProviderErrors",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(mock.NewErroringSelectionProofDomainProvider()),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain selection proof domain: error",
		},
		{
			name: "AggregateAndProofDomainProviderMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "problem with parameters: no aggregate and proof domain provider specified",
		},
		{
			name: "AggregateAndProofDomainProviderErrors",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(mock.NewErroringAggregateAndProofDomainProvider()),
				dirk.WithDomainProvider(domainProvider),
			},
			err: "failed to obtain aggregate and proof domain: error",
		},
		{
			name: "DomainProviderMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
			},
			err: "problem with parameters: no domain provider specified",
		},
		{
			name: "Good",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.Disabled),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(validatorsProvider),
				dirk.WithSlotsPerEpochProvider(slotsPerEpochProvider),
				dirk.WithBeaconProposerDomainProvider(beaconProposerDomainProvider),
				dirk.WithBeaconAttesterDomainProvider(beaconAttesterDomainProvider),
				dirk.WithRANDAODomainProvider(randaoDomainProvider),
				dirk.WithSelectionProofDomainProvider(selectionProofDomainProvider),
				dirk.WithAggregateAndProofDomainProvider(aggregateAndProofDomainProvider),
				dirk.WithDomainProvider(domainProvider),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			_, err := dirk.New(context.Background(), test.params...)
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

func TestAccounts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port := uint32(1024 + rand.Intn(15359))
	_, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("server-test01:%d", port)})
	require.Nil(t, err)

	tests := []struct {
		name         string
		accountPaths []string
		accounts     int
	}{
		{
			name:         "Empty",
			accountPaths: []string{"None"},
			accounts:     0,
		},
		{
			name:         "Wallet1",
			accountPaths: []string{"Wallet 1"},
			accounts:     16,
		},
		{
			name:         "Wallet1OddAccounts",
			accountPaths: []string{"Wallet 1/Account .*[13579]"},
			accounts:     8,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := dirk.New(context.Background(),
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{fmt.Sprintf("signer-test01:%d", port)}),
				dirk.WithAccountPaths(test.accountPaths),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(mock.NewValidatorsProvider()),
				dirk.WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
				dirk.WithBeaconProposerDomainProvider(mock.NewBeaconProposerDomainProvider()),
				dirk.WithBeaconAttesterDomainProvider(mock.NewBeaconAttesterDomainProvider()),
				dirk.WithRANDAODomainProvider(mock.NewRANDAODomainProvider()),
				dirk.WithSelectionProofDomainProvider(mock.NewSelectionProofDomainProvider()),
				dirk.WithAggregateAndProofDomainProvider(mock.NewAggregateAndProofDomainProvider()),
				dirk.WithDomainProvider(mock.NewDomainProvider()),
			)
			require.Nil(t, err)

			accounts, err := s.Accounts(ctx)
			require.Nil(t, err)
			require.Equal(t, test.accounts, len(accounts))
		})
	}
}

func TestAccountsByIndex(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port := uint32(1024 + rand.Intn(15359))
	_, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("server-test01:%d", port)})
	require.Nil(t, err)

	tests := []struct {
		name     string
		indices  []spec.ValidatorIndex
		accounts int
	}{
		{
			name:     "Nil",
			accounts: 0,
		},
		{
			name:     "Empty",
			indices:  []spec.ValidatorIndex{},
			accounts: 0,
		},
		{
			name:     "All",
			indices:  []spec.ValidatorIndex{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			accounts: 16,
		},
		{
			name:     "Missing",
			indices:  []spec.ValidatorIndex{15, 16},
			accounts: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := dirk.New(context.Background(),
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{fmt.Sprintf("signer-test01:%d", port)}),
				dirk.WithAccountPaths([]string{"Wallet 1"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(mock.NewValidatorsProvider()),
				dirk.WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
				dirk.WithBeaconProposerDomainProvider(mock.NewBeaconProposerDomainProvider()),
				dirk.WithBeaconAttesterDomainProvider(mock.NewBeaconAttesterDomainProvider()),
				dirk.WithRANDAODomainProvider(mock.NewRANDAODomainProvider()),
				dirk.WithSelectionProofDomainProvider(mock.NewSelectionProofDomainProvider()),
				dirk.WithAggregateAndProofDomainProvider(mock.NewAggregateAndProofDomainProvider()),
				dirk.WithDomainProvider(mock.NewDomainProvider()),
			)
			require.Nil(t, err)

			accounts, err := s.AccountsByIndex(ctx, test.indices)
			require.Nil(t, err)
			require.Equal(t, test.accounts, len(accounts))
		})
	}
}

func TestAccountsByPubKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port := uint32(1024 + rand.Intn(15359))
	_, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("server-test01:%d", port)})
	require.Nil(t, err)

	tests := []struct {
		name     string
		pubKeys  []spec.BLSPubKey
		accounts int
	}{
		{
			name:     "Nil",
			accounts: 0,
		},
		{
			name: "Empty",
			pubKeys: []spec.BLSPubKey{
				{},
			},
			accounts: 0,
		},
		{
			name: "All",
			pubKeys: []spec.BLSPubKey{
				testutil.HexToPubKey("0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"),
				testutil.HexToPubKey("0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"),
				testutil.HexToPubKey("0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b"),
				testutil.HexToPubKey("0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e"),
				testutil.HexToPubKey("0x81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e"),
				testutil.HexToPubKey("0xab0bdda0f85f842f431beaccf1250bf1fd7ba51b4100fd64364b6401fda85bb0069b3e715b58819684e7fc0b10a72a34"),
				testutil.HexToPubKey("0x9977f1c8b731a8d5558146bfb86caea26434f3c5878b589bf280a42c9159e700e9df0e4086296c20b011d2e78c27d373"),
				testutil.HexToPubKey("0xa8d4c7c27795a725961317ef5953a7032ed6d83739db8b0e8a72353d1b8b4439427f7efa2c89caa03cc9f28f8cbab8ac"),
				testutil.HexToPubKey("0xa6d310dbbfab9a22450f59993f87a4ce5db6223f3b5f1f30d2c4ec718922d400e0b3c7741de8e59960f72411a0ee10a7"),
				testutil.HexToPubKey("0x9893413c00283a3f9ed9fd9845dda1cea38228d22567f9541dccc357e54a2d6a6e204103c92564cbc05f4905ac7c493a"),
				testutil.HexToPubKey("0x876dd4705157eb66dc71bc2e07fb151ea53e1a62a0bb980a7ce72d15f58944a8a3752d754f52f4a60dbfc7b18169f268"),
				testutil.HexToPubKey("0xaec922bd7a9b7b1dc21993133b586b0c3041c1e2e04b513e862227b9d7aecaf9444222f7e78282a449622ffc6278915d"),
				testutil.HexToPubKey("0x9314c6de0386635e2799af798884c2ea09c63b9f079e572acc00b06a7faccce501ea4dfc0b1a23b8603680a5e3481327"),
				testutil.HexToPubKey("0x903e2989e7442ee0a8958d020507a8bd985d3974f5e8273093be00db3935f0500e141b252bd09e3728892c7a8443863c"),
				testutil.HexToPubKey("0x84398f539a64cbe01cfcd8c485ea51cd6657b94df93ee9b5dc61e1f18f69da6ca9d4dba63c956a81c68d5d4d4277a60f"),
				testutil.HexToPubKey("0x872c61b4a7f8510ec809e5b023f5fdda2105d024c470ddbbeca4bc74e8280af0d178d749853e8f6a841083ac1b4db98f"),
			},
			accounts: 16,
		},
		{
			name: "Missing",
			pubKeys: []spec.BLSPubKey{
				testutil.HexToPubKey("0x872c61b4a7f8510ec809e5b023f5fdda2105d024c470ddbbeca4bc74e8280af0d178d749853e8f6a841083ac1b4db98f"),
				testutil.HexToPubKey("0x8f467e5723deac7659e1ca273e28410cbaa6d495ab66ae77014f4cd21c64b6b5ab9987c9b5537fe0279bd063fe609be7"),
			},
			accounts: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := dirk.New(context.Background(),
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(context.Background())),
				dirk.WithClientMonitor(nullmetrics.New(context.Background())),
				dirk.WithEndpoints([]string{fmt.Sprintf("signer-test01:%d", port)}),
				dirk.WithAccountPaths([]string{"Wallet 1"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsProvider(mock.NewValidatorsProvider()),
				dirk.WithSlotsPerEpochProvider(mock.NewSlotsPerEpochProvider(32)),
				dirk.WithBeaconProposerDomainProvider(mock.NewBeaconProposerDomainProvider()),
				dirk.WithBeaconAttesterDomainProvider(mock.NewBeaconAttesterDomainProvider()),
				dirk.WithRANDAODomainProvider(mock.NewRANDAODomainProvider()),
				dirk.WithSelectionProofDomainProvider(mock.NewSelectionProofDomainProvider()),
				dirk.WithAggregateAndProofDomainProvider(mock.NewAggregateAndProofDomainProvider()),
				dirk.WithDomainProvider(mock.NewDomainProvider()),
			)
			require.Nil(t, err)

			accounts, err := s.AccountsByPubKey(ctx, test.pubKeys)
			require.Nil(t, err)
			require.Equal(t, test.accounts, len(accounts))
		})
	}
}
