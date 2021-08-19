// Copyright © 2020, 2021 Attestant Limited.
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
	"testing"
	"time"

	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/accountmanager/dirk"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/attestantio/vouch/testing/resources"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	slotDuration := 12 * time.Second
	slotsPerEpoch := uint64(32)
	mockGenesisTimeProvider := mock.NewGenesisTimeProvider(genesisTime)
	mockSlotDurationProvider := mock.NewSlotDurationProvider(slotDuration)
	mockSlotsPerEpochProvider := mock.NewSlotsPerEpochProvider(slotsPerEpoch)

	domainProvider := mock.NewDomainProvider()
	validatorsManager := mock.NewValidatorsManager()
	farFutureEpochProvider := mock.NewFarFutureEpochProvider(0xffffffffffffffff)
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithGenesisTimeProvider(mockGenesisTimeProvider),
		standardchaintime.WithSlotDurationProvider(mockSlotDurationProvider),
		standardchaintime.WithSlotsPerEpochProvider(mockSlotsPerEpochProvider),
	)
	require.NoError(t, err)

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
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ClientMonitorNil",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nil),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no client monitor specified",
		},
		{
			name: "ProcessConcurrencyZero",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(0),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no process concurrency specified",
		},
		{
			name: "EndpointsNil",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no endpoints specified",
		},
		{
			name: "EndpointsEmpty",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no endpoints specified",
		},
		{
			name: "EndpointsMalformedEndpoint",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{""}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err:      "no valid endpoints specified",
			logEntry: "Malformed endpoint",
		},
		{
			name: "EndpointsMalformedPort",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"host:bad"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err:      "no valid endpoints specified",
			logEntry: "Malformed port",
		},
		{
			name: "EndpointsInvalidPort",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"host:0"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err:      "no valid endpoints specified",
			logEntry: "Invalid port",
		},
		{
			name: "AccountPathsNil",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no account paths specified",
		},
		{
			name: "AccountPathsEmpty",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no account paths specified",
		},
		{
			name: "ClientCertMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no client certificate specified",
		},
		{
			name: "ClientKeyMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no client key specified",
		},
		{
			name: "ClientCertKeyMismatch",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.Disabled),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest02Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "failed to build credentials: failed to load client keypair: tls: private key does not match public key",
		},
		{
			name: "ValidatorsManagerMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no validators manager specified",
		},
		{
			name: "DomainProviderMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no domain provider specified",
		},
		{
			name: "FarFutureEpochProviderMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no far future epoch provider specified",
		},
		{
			name: "CurrentEpochProviderMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.Disabled),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
			},
			err: "problem with parameters: no current epoch provider specified",
		},
		{
			name: "Good",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.Disabled),
				dirk.WithMonitor(nullmetrics.New(ctx)),
				dirk.WithClientMonitor(nullmetrics.New(ctx)),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCert([]byte(resources.ClientTest01Crt)),
				dirk.WithClientKey([]byte(resources.ClientTest01Key)),
				dirk.WithCACert([]byte(resources.CACrt)),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			_, err := dirk.New(ctx, test.params...)
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
