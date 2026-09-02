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

package standard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// prewarmService creates a service with only the fields that pre-warming uses.
func prewarmService(addresses []string) *Service {
	return &Service{
		log:              zerolog.Nop(),
		prewarmAddresses: addresses,
		prewarmClient:    &http.Client{Timeout: prewarmTimeout},
	}
}

func TestPrewarmBaseURL(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		expected string
	}{
		{
			name:     "HostAndPort",
			address:  "localhost:5052",
			expected: "http://localhost:5052",
		},
		{
			name:     "HTTPScheme",
			address:  "http://localhost:5052",
			expected: "http://localhost:5052",
		},
		{
			name:     "HTTPSScheme",
			address:  "https://beacon.example.com",
			expected: "https://beacon.example.com",
		},
		{
			name:     "TrailingSlash",
			address:  "localhost:5052/",
			expected: "http://localhost:5052",
		},
		{
			name:     "SchemeAndTrailingSlash",
			address:  "http://localhost:5052/",
			expected: "http://localhost:5052",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, prewarmBaseURL(test.address))
		})
	}
}

func TestPrewarmRequest(t *testing.T) {
	ctx := context.Background()

	var mu sync.Mutex
	requests := make([]*url.URL, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	randaoReveal := phase0.BLSSignature{0x01, 0x02, 0x03}
	prewarmService([]string{server.URL}).prewarm(ctx, duty(12345, 2, randaoReveal, nil))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, requests, 1)
	require.Equal(t, "/eth/v2/validator/blocks/12345", requests[0].Path)
	require.Equal(t, randaoReveal.String(), requests[0].Query().Get("randao_reveal"))
}

func TestPrewarmNoAddresses(t *testing.T) {
	ctx := context.Background()

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	prewarmService(nil).prewarm(ctx, duty(1, 2, phase0.BLSSignature{}, nil))

	require.Equal(t, int32(0), hits.Load())
}

func TestPrewarmAllAddresses(t *testing.T) {
	ctx := context.Background()

	var first, second atomic.Int32
	firstServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		first.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer firstServer.Close()
	secondServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		second.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer secondServer.Close()

	prewarmService([]string{firstServer.URL, secondServer.URL}).prewarm(ctx, duty(1, 2, phase0.BLSSignature{}, nil))

	require.Equal(t, int32(1), first.Load())
	require.Equal(t, int32(1), second.Load())
}

// TestPrewarmContinuesAfterFailure confirms that an unhealthy beacon node neither
// stops the others from being pre-warmed nor propagates its failure.
func TestPrewarmContinuesAfterFailure(t *testing.T) {
	ctx := context.Background()

	var hits atomic.Int32
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()

	erroring := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer erroring.Close()

	// An address on which nothing is listening.
	unreachable := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	unreachableAddress := unreachable.URL
	unreachable.Close()

	service := prewarmService([]string{erroring.URL, unreachableAddress, healthy.URL})
	require.NotPanics(t, func() {
		service.prewarm(ctx, duty(1, 2, phase0.BLSSignature{}, nil))
	})

	require.Equal(t, int32(1), hits.Load())
}

// TestPrewarmIgnoresContextCancellation confirms that pre-warming is not tied to the
// lifetime of the proposal that triggered it.
func TestPrewarmIgnoresContextCancellation(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	prewarmService([]string{server.URL}).prewarm(ctx, duty(1, 2, phase0.BLSSignature{}, nil))

	require.Equal(t, int32(1), hits.Load())
}
