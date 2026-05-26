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

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	certtesting "github.com/attestantio/go-certmanager/testing"
	certmock "github.com/attestantio/go-certmanager/testing/mock"
	"github.com/attestantio/vouch/services/metrics"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// tracingStubMonitor is a monitor with a configurable presenter, used to opt
// into go-certmanager metric registration during tests.
// Mirrors stubMonitor in services/accountmanager/dirk/service_test.go.
type tracingStubMonitor struct{ presenter string }

func (s tracingStubMonitor) Presenter() string { return s.presenter }

var _ metrics.Service = tracingStubMonitor{}

func TestLoadTracingClientCertificatesHappy(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
	})

	ctx := context.Background()
	majordomo := certmock.NewMajordomo(map[string][]byte{
		"tracing-client-cert": []byte(certtesting.ClientTest01Crt),
		"tracing-client-key":  []byte(certtesting.ClientTest01Key),
	})

	viper.Set("tracing.client-cert", "tracing-client-cert")
	viper.Set("tracing.client-key", "tracing-client-key")

	creds, err := loadTracingClientCertificates(ctx, majordomo, nullmetrics.New())
	require.NoError(t, err)
	require.NotNil(t, creds)
}

func TestLoadTracingClientCertificatesHappyWithCA(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
	})

	ctx := context.Background()
	majordomo := certmock.NewMajordomo(map[string][]byte{
		"tracing-client-cert": []byte(certtesting.ClientTest01Crt),
		"tracing-client-key":  []byte(certtesting.ClientTest01Key),
		"tracing-ca-cert":     []byte(certtesting.CACrt),
	})

	viper.Set("tracing.client-cert", "tracing-client-cert")
	viper.Set("tracing.client-key", "tracing-client-key")
	viper.Set("tracing.ca-cert", "tracing-ca-cert")

	creds, err := loadTracingClientCertificates(ctx, majordomo, nullmetrics.New())
	require.NoError(t, err)
	require.NotNil(t, creds)
}

func TestLoadTracingClientCertificatesMajordomoError(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
	})

	ctx := context.Background()
	majordomo := certmock.NewMajordomoWithError(errors.New("fetch failed"))

	viper.Set("tracing.client-cert", "tracing-client-cert")
	viper.Set("tracing.client-key", "tracing-client-key")
	viper.Set("tracing.ca-cert", "tracing-ca-cert")

	creds, err := loadTracingClientCertificates(ctx, majordomo, nullmetrics.New())
	require.Error(t, err)
	require.Nil(t, creds)
	require.Contains(t, err.Error(), "fetch failed")
}

func TestLoadTracingClientCertificatesWithPrometheusMonitor(t *testing.T) {
	// Passing a monitor whose presenter is "prometheus" opts into go-certmanager's
	// metric registration. Asserts the tracing client certificate expiry gauges
	// are registered under name="tracing", role="client". Guards both the
	// WithMonitor and WithName wiring — missing either would cause the series to
	// be absent (WithMonitor) or construction to fail (WithName).
	t.Cleanup(func() {
		viper.Reset()
	})

	ctx := context.Background()
	majordomo := certmock.NewMajordomo(map[string][]byte{
		"tracing-client-cert": []byte(certtesting.ClientTest01Crt),
		"tracing-client-key":  []byte(certtesting.ClientTest01Key),
	})

	viper.Set("tracing.client-cert", "tracing-client-cert")
	viper.Set("tracing.client-key", "tracing-client-key")

	creds, err := loadTracingClientCertificates(ctx, majordomo, tracingStubMonitor{presenter: "prometheus"})
	require.NoError(t, err)
	require.NotNil(t, creds)

	requireTracingCertMetric(t, "certmanager_certificate_not_after_seconds", "tracing", "client")
	requireTracingCertMetric(t, "certmanager_certificate_not_before_seconds", "tracing", "client")
}

// requireTracingCertMetric asserts the go-certmanager gauge series with the given
// name/role labels is present in the default Prometheus registry and has a
// positive value (i.e. SetCertificateExpiry was invoked).
func requireTracingCertMetric(t *testing.T, metricName, name, role string) {
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

	var seen []string
	for _, mf := range families {
		if strings.HasPrefix(mf.GetName(), "certmanager_") {
			for _, m := range mf.GetMetric() {
				seen = append(seen, m.String())
			}
		}
	}
	t.Fatalf("metric %s{name=%q,role=%q} not registered (saw: %v)", metricName, name, role, seen)
}
