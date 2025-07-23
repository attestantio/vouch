// Copyright © 2025 Attestant Limited.
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

package util_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/attestantio/vouch/util"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// mockMonitor is a mock implementation of metrics.Service for testing.
type mockMonitor struct{}

func (*mockMonitor) Presenter() string                    { return "mock" }
func (*mockMonitor) Gauge(string) func(float64)           { return func(float64) {} }
func (*mockMonitor) Counter(string) func(uint64)          { return func(uint64) {} }
func (*mockMonitor) Histogram(string) func(time.Duration) { return func(time.Duration) {} }

// setupViperDefaults sets up common viper defaults for tests.
func setupViperDefaults() {
	viper.Reset()
	viper.SetDefault("timeout", "2s")
	util.SetServiceDefaults()
}

// createMockServer creates a simple HTTP test server.
func createMockServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func TestTimeoutHierarchy(t *testing.T) {
	tests := []struct {
		name     string
		vars     map[string]string
		address  string
		expected time.Duration
	}{
		{
			name:     "EmptyAddress",
			address:  "",
			expected: 2 * time.Second,
		},
		{
			name: "GlobalBuilderClientTimeout",
			vars: map[string]string{
				"timeout":               "2s",
				"builderclient.timeout": "5s",
			},
			address:  "relay.example.com",
			expected: 5 * time.Second,
		},
		{
			name: "SpecificRelayTimeout",
			vars: map[string]string{
				"timeout":               "2s",
				"builderclient.timeout": "5s",
				"builderclient.relay.example.com.timeout": "3s",
			},
			address:  "relay.example.com",
			expected: 3 * time.Second,
		},
		{
			name: "FallbackToServiceGlobal",
			vars: map[string]string{
				"timeout":               "2s",
				"builderclient.timeout": "5s",
				"builderclient.submitvalidatorregistrations.timeout": "30s",
			},
			address:  "relay.example.com",
			expected: 5 * time.Second,
		},
		{
			name: "FallbackToGlobalDefault",
			vars: map[string]string{
				"timeout": "10s",
			},
			address:  "relay.example.com",
			expected: 10 * time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setupViperDefaults()

			for k, v := range test.vars {
				viper.Set(k, v)
			}

			timeoutPath := fmt.Sprintf("builderclient.%s", test.address)
			timeout := util.Timeout(timeoutPath)
			require.Equal(t, test.expected, timeout)
		})
	}
}

func TestTimeoutWithServices(t *testing.T) {
	tests := []struct {
		name     string
		vars     map[string]string
		service  string
		address  string
		expected time.Duration
	}{
		{
			name: "SubmitValidatorRegistrations",
			vars: map[string]string{
				"timeout":               "2s",
				"builderclient.timeout": "5s",
				"builderclient.submitvalidatorregistrations.timeout":                   "30s",
				"builderclient.submitvalidatorregistrations.relay.example.com.timeout": "20s",
			},
			service:  "submitvalidatorregistrations",
			address:  "relay.example.com",
			expected: 20 * time.Second,
		},
		{
			name: "SubmitValidatorRegistrationsWithoutAddress",
			vars: map[string]string{
				"timeout":               "2s",
				"builderclient.timeout": "5s",
				"builderclient.submitvalidatorregistrations.timeout":                   "30s",
				"builderclient.submitvalidatorregistrations.relay.example.com.timeout": "20s",
			},
			service:  "submitvalidatorregistrations",
			address:  "",
			expected: 30 * time.Second,
		},
		{
			name: "BuilderBidStrategy",
			vars: map[string]string{
				"timeout":               "2s",
				"builderclient.timeout": "5s",
				"builderclient.strategies.builderbid.timeout": "1s",
			},
			service:  "strategies.builderbid",
			address:  "",
			expected: 1 * time.Second,
		},
		{
			name: "BlockRelay",
			vars: map[string]string{
				"timeout":                          "2s",
				"builderclient.timeout":            "5s",
				"builderclient.blockrelay.timeout": "4s",
			},
			service:  "blockrelay",
			address:  "",
			expected: 4 * time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setupViperDefaults()

			for k, v := range test.vars {
				viper.Set(k, v)
			}

			ctx := context.Background()
			monitor := &mockMonitor{}
			server := createMockServer()
			defer server.Close()

			_, err := util.FetchBuilderClient(ctx, test.service, server.URL, monitor, "test-version")
			require.NoError(t, err)

			timeoutPath := fmt.Sprintf("builderclient.%s.%s", test.service, test.address)
			timeout := util.Timeout(timeoutPath)
			require.Equal(t, test.expected, timeout)
		})
	}
}

func TestServiceDefaultTimeouts(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		expected time.Duration
	}{
		{
			name:     "BlockRelayDefault",
			service:  "blockrelay",
			expected: 10 * time.Second,
		},
		{
			name:     "SubmitValidatorRegistrationsDefault",
			service:  "submitvalidatorregistrations",
			expected: 5 * time.Second,
		},
		{
			name:     "StrategiesBuilderbidDefault",
			service:  "strategies.builderbid",
			expected: 5 * time.Second,
		},
		{
			name:     "UnknownServiceNoDefault",
			service:  "unknownservice",
			expected: 2 * time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setupViperDefaults()

			ctx := context.Background()
			monitor := &mockMonitor{}
			server := createMockServer()
			defer server.Close()

			client, err := util.FetchBuilderClient(ctx, test.service, server.URL, monitor, "test-version")
			require.NoError(t, err)
			require.NotNil(t, client)

			timeoutPath := fmt.Sprintf("builderclient.%s.%s", test.service, server.URL)
			timeout := util.Timeout(timeoutPath)
			require.Equal(t, test.expected, timeout, "Service: %s", test.service)
		})
	}
}
