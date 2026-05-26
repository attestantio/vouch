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

package dirk_test

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	standardclientcert "github.com/attestantio/go-certmanager/client/standard"
	certtesting "github.com/attestantio/go-certmanager/testing"
	certmock "github.com/attestantio/go-certmanager/testing/mock"
	"github.com/attestantio/vouch/mock"
	"github.com/attestantio/vouch/services/accountmanager/dirk"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// stubMonitor is a monitor that reports a fixed presenter; used to opt into
// go-certmanager metric registration during tests.
// Mirrors tracingStubMonitor in tracing_test.go.
type stubMonitor struct{ presenter string }

func (s stubMonitor) Presenter() string { return s.presenter }

var _ metrics.Service = stubMonitor{}

// newTestMajordomo creates a mock majordomo with matching test certificates.
func newTestMajordomo() *certmock.Majordomo {
	return certmock.NewMajordomo(map[string][]byte{
		"client-cert": []byte(certtesting.ClientTest01Crt),
		"client-key":  []byte(certtesting.ClientTest01Key),
		"ca-cert":     []byte(certtesting.CACrt),
	})
}

// newMismatchedMajordomo creates a mock majordomo with mismatched cert/key.
func newMismatchedMajordomo() *certmock.Majordomo {
	return certmock.NewMajordomo(map[string][]byte{
		"client-cert": []byte(certtesting.ClientTest01Crt),
		"client-key":  []byte(certtesting.ClientTest02Key),
		"ca-cert":     []byte(certtesting.CACrt),
	})
}

func TestService(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	domainProvider := mock.NewDomainProvider()
	validatorsManager := mock.NewValidatorsManager()
	farFutureEpochProvider := mock.NewFarFutureEpochProvider(0xffffffffffffffff)
	mdm := newTestMajordomo()

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
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nil),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(0),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{""}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"host:bad"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"host:0"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no account paths specified",
		},
		{
			name: "MajordomoMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no majordomo specified",
		},
		{
			name: "ClientCertURIMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no client certificate URI specified",
		},
		{
			name: "ClientKeyURIMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithCACertURI("ca-cert"),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "problem with parameters: no client key URI specified",
		},
		{
			name: "ClientCertKeyMismatch",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.Disabled),
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(newMismatchedMajordomo()),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
				dirk.WithValidatorsManager(validatorsManager),
				dirk.WithDomainProvider(domainProvider),
				dirk.WithFarFutureEpochProvider(farFutureEpochProvider),
				dirk.WithCurrentEpochProvider(chainTime),
			},
			err: "failed to create client certificate manager: failed to load client keypair: tls: private key does not match public key",
		},
		{
			name: "ValidatorsManagerMissing",
			params: []dirk.Parameter{
				dirk.WithLogLevel(zerolog.TraceLevel),
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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
				dirk.WithMonitor(nullmetrics.New()),
				dirk.WithClientMonitor(nullmetrics.New()),
				dirk.WithProcessConcurrency(1),
				dirk.WithEndpoints([]string{"localhost:12345", "localhost:12346"}),
				dirk.WithAccountPaths([]string{"wallet1", "wallet2"}),
				dirk.WithMajordomo(mdm),
				dirk.WithClientCertURI("client-cert"),
				dirk.WithClientKeyURI("client-key"),
				dirk.WithCACertURI("ca-cert"),
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

func TestDirkTLSWiringHappy(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	svc, err := dirk.New(ctx,
		dirk.WithLogLevel(zerolog.TraceLevel),
		dirk.WithMonitor(nullmetrics.New()),
		dirk.WithClientMonitor(nullmetrics.New()),
		dirk.WithProcessConcurrency(1),
		dirk.WithEndpoints([]string{"localhost:12345"}),
		dirk.WithAccountPaths([]string{"wallet1"}),
		dirk.WithMajordomo(newTestMajordomo()),
		dirk.WithClientCertURI("client-cert"),
		dirk.WithClientKeyURI("client-key"),
		dirk.WithCACertURI("ca-cert"),
		dirk.WithValidatorsManager(mock.NewValidatorsManager()),
		dirk.WithDomainProvider(mock.NewDomainProvider()),
		dirk.WithFarFutureEpochProvider(mock.NewFarFutureEpochProvider(0xffffffffffffffff)),
		dirk.WithCurrentEpochProvider(chainTime),
	)
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestDirkTLSKeypairMismatch(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	_, err = dirk.New(ctx,
		dirk.WithLogLevel(zerolog.Disabled),
		dirk.WithMonitor(nullmetrics.New()),
		dirk.WithClientMonitor(nullmetrics.New()),
		dirk.WithProcessConcurrency(1),
		dirk.WithEndpoints([]string{"localhost:12345"}),
		dirk.WithAccountPaths([]string{"wallet1"}),
		dirk.WithMajordomo(newMismatchedMajordomo()),
		dirk.WithClientCertURI("client-cert"),
		dirk.WithClientKeyURI("client-key"),
		dirk.WithCACertURI("ca-cert"),
		dirk.WithValidatorsManager(mock.NewValidatorsManager()),
		dirk.WithDomainProvider(mock.NewDomainProvider()),
		dirk.WithFarFutureEpochProvider(mock.NewFarFutureEpochProvider(0xffffffffffffffff)),
		dirk.WithCurrentEpochProvider(chainTime),
	)
	require.EqualError(t, err, "failed to create client certificate manager: failed to load client keypair: tls: private key does not match public key")
}

func TestDirkTLSCAOptional(t *testing.T) {
	ctx := context.Background()

	genesisTime := time.Now()
	genesisProvider := mock.NewGenesisProvider(genesisTime)
	specProvider := mock.NewSpecProvider()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(genesisProvider),
		standardchaintime.WithSpecProvider(specProvider),
	)
	require.NoError(t, err)

	t.Run("NoCA", func(t *testing.T) {
		svc, err := dirk.New(ctx,
			dirk.WithLogLevel(zerolog.Disabled),
			dirk.WithMonitor(nullmetrics.New()),
			dirk.WithClientMonitor(nullmetrics.New()),
			dirk.WithProcessConcurrency(1),
			dirk.WithEndpoints([]string{"localhost:12345"}),
			dirk.WithAccountPaths([]string{"wallet1"}),
			dirk.WithMajordomo(newTestMajordomo()),
			dirk.WithClientCertURI("client-cert"),
			dirk.WithClientKeyURI("client-key"),
			dirk.WithValidatorsManager(mock.NewValidatorsManager()),
			dirk.WithDomainProvider(mock.NewDomainProvider()),
			dirk.WithFarFutureEpochProvider(mock.NewFarFutureEpochProvider(0xffffffffffffffff)),
			dirk.WithCurrentEpochProvider(chainTime),
		)
		require.NoError(t, err)
		require.NotNil(t, svc)
	})

	t.Run("WithCA", func(t *testing.T) {
		svc, err := dirk.New(ctx,
			dirk.WithLogLevel(zerolog.Disabled),
			dirk.WithMonitor(nullmetrics.New()),
			dirk.WithClientMonitor(nullmetrics.New()),
			dirk.WithProcessConcurrency(1),
			dirk.WithEndpoints([]string{"localhost:12345"}),
			dirk.WithAccountPaths([]string{"wallet1"}),
			dirk.WithMajordomo(newTestMajordomo()),
			dirk.WithClientCertURI("client-cert"),
			dirk.WithClientKeyURI("client-key"),
			dirk.WithCACertURI("ca-cert"),
			dirk.WithValidatorsManager(mock.NewValidatorsManager()),
			dirk.WithDomainProvider(mock.NewDomainProvider()),
			dirk.WithFarFutureEpochProvider(mock.NewFarFutureEpochProvider(0xffffffffffffffff)),
			dirk.WithCurrentEpochProvider(chainTime),
		)
		require.NoError(t, err)
		require.NotNil(t, svc)
	})
}

func TestDirkTLSWiringWithPrometheusMonitor(t *testing.T) {
	// Passing a monitor whose presenter is "prometheus" opts into go-certmanager's
	// metric registration. Asserts the client certificate expiry gauges are
	// registered under name="dirk", role="client". Guards both the WithMonitor
	// and WithName wiring — missing either would cause the series to be absent
	// (WithMonitor) or construction to fail with ErrNoNameWithMonitor (WithName).
	ctx := context.Background()

	genesisTime := time.Now()
	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithLogLevel(zerolog.Disabled),
		standardchaintime.WithGenesisProvider(mock.NewGenesisProvider(genesisTime)),
		standardchaintime.WithSpecProvider(mock.NewSpecProvider()),
	)
	require.NoError(t, err)

	svc, err := dirk.New(ctx,
		dirk.WithLogLevel(zerolog.Disabled),
		dirk.WithMonitor(stubMonitor{presenter: "prometheus"}),
		dirk.WithClientMonitor(nullmetrics.New()),
		dirk.WithProcessConcurrency(1),
		dirk.WithEndpoints([]string{"localhost:12345"}),
		dirk.WithAccountPaths([]string{"wallet1"}),
		dirk.WithMajordomo(newTestMajordomo()),
		dirk.WithClientCertURI("client-cert"),
		dirk.WithClientKeyURI("client-key"),
		dirk.WithCACertURI("ca-cert"),
		dirk.WithValidatorsManager(mock.NewValidatorsManager()),
		dirk.WithDomainProvider(mock.NewDomainProvider()),
		dirk.WithFarFutureEpochProvider(mock.NewFarFutureEpochProvider(0xffffffffffffffff)),
		dirk.WithCurrentEpochProvider(chainTime),
	)
	require.NoError(t, err)
	require.NotNil(t, svc)

	requireCertMetric(t, "certmanager_certificate_not_after_seconds", "dirk", "client")
	requireCertMetric(t, "certmanager_certificate_not_before_seconds", "dirk", "client")
}

// requireCertMetric asserts the go-certmanager gauge series with the given
// name/role labels is present in the default Prometheus registry and has a
// positive value (i.e. SetCertificateExpiry was invoked).
func requireCertMetric(t *testing.T, metricName, name, role string) {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	for _, mf := range families {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			var matchName, matchRole bool
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "name":
					matchName = l.GetValue() == name
				case "role":
					matchRole = l.GetValue() == role
				}
			}
			if matchName && matchRole {
				require.Greater(t, m.GetGauge().GetValue(), float64(0),
					"metric %s{name=%q,role=%q} should have a positive value", metricName, name, role)
				return
			}
		}
	}

	var found []string
	for _, mf := range families {
		if strings.HasPrefix(mf.GetName(), "certmanager_") {
			for _, m := range mf.GetMetric() {
				found = append(found, m.String())
			}
		}
	}
	t.Fatalf("metric %s{name=%q,role=%q} not registered (saw certmanager_ series: %v)",
		metricName, name, role, found)
}

func TestDirkTLSMinVersion(t *testing.T) {
	ctx := context.Background()

	mdm := certmock.NewMajordomo(map[string][]byte{
		"client-cert": []byte(certtesting.ClientTest01Crt),
		"client-key":  []byte(certtesting.ClientTest01Key),
		"ca-cert":     []byte(certtesting.CACrt),
	})

	clientCertMgr, err := standardclientcert.New(ctx,
		standardclientcert.WithMajordomo(mdm),
		standardclientcert.WithCertPEMURI("client-cert"),
		standardclientcert.WithCertKeyURI("client-key"),
		standardclientcert.WithCACertURI("ca-cert"),
	)
	require.NoError(t, err)

	tlsCfg, err := clientCertMgr.GetTLSConfig(ctx)
	require.NoError(t, err)

	require.Equal(t, uint16(tls.VersionTLS13), tlsCfg.MinVersion)
	require.NotNil(t, tlsCfg.Certificates)
	require.Greater(t, len(tlsCfg.Certificates), 0)
}
