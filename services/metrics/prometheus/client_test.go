// Copyright © 2021 Attestant Limited.
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

package prometheus

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestClientOperationHidesConfiguredBeaconNode(t *testing.T) {
	viper.Set("beacon-node-addresses", []string{"https://private.example:5052"})
	t.Cleanup(func() { viper.Reset() })

	service, err := New(context.Background(), WithAddress("localhost:0"))
	require.NoError(t, err)
	service.ClientOperation("https://private.example:5052", "test beacon privacy", true, time.Millisecond)
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	var provider string
	for _, family := range families {
		if family.GetName() != "vouch_client_operation_requests_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "operation" && label.GetValue() == "test beacon privacy" {
					for _, candidate := range metric.GetLabel() {
						if candidate.GetName() == "provider" {
							provider = candidate.GetValue()
						}
					}
				}
			}
		}
	}
	require.Equal(t, "beacon-1", provider)
}

func TestStrategyOperationHidesConfiguredBeaconNode(t *testing.T) {
	viper.Set("beacon-node-addresses", []string{"https://private.example:5052"})
	t.Cleanup(func() { viper.Reset() })

	service, err := New(context.Background(), WithAddress("localhost:0"))
	require.NoError(t, err)
	service.StrategyOperation("best", "https://private.example:5052", "test strategy privacy", time.Millisecond)
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	var provider string
	for _, family := range families {
		if family.GetName() != "vouch_strategy_operation_used_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "operation" && label.GetValue() == "test strategy privacy" {
					for _, candidate := range metric.GetLabel() {
						if candidate.GetName() == "provider" {
							provider = candidate.GetValue()
						}
					}
				}
			}
		}
	}
	require.Equal(t, "beacon-1", provider)
}

func TestParseAddress(t *testing.T) {
	provider := "eth-val-d03-01.attestant.io:15100"
	url, err := parseAddress(provider)
	require.NoError(t, err)
	require.Equal(t, "http://eth-val-d03-01.attestant.io:15100", url.String())

}
