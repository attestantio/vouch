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
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func TestMonitorGloasProposalSelectionBoundsLabels(t *testing.T) {
	previous := gloasProposalSelections
	gloasProposalSelections = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_gloas_selections_total"}, []string{"strategy", "requested_preference", "source"})
	t.Cleanup(func() {
		gloasProposalSelections = previous
	})

	monitorGloasProposalSelection("injected-strategy", "injected-preference", "injected-source")

	metric := &dto.Metric{}
	counter, err := gloasProposalSelections.GetMetricWithLabelValues("unknown", "unknown", "unknown")
	require.NoError(t, err)
	require.NoError(t, counter.Write(metric))
	require.Equal(t, float64(1), metric.GetCounter().GetValue())
}

func TestGloasRequestedPreference(t *testing.T) {
	tests := []struct {
		name     string
		boost    uint64
		expected string
	}{
		{
			name:     "SelfBuildPreferred",
			boost:    99,
			expected: "self_build_preferred",
		},
		{
			name:     "ValueMaximizing",
			boost:    100,
			expected: "value_maximizing",
		},
		{
			name:     "BuilderPreferred",
			boost:    101,
			expected: "builder_preferred",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, gloasRequestedPreference(test.boost))
		})
	}
}
