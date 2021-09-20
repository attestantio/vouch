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

package util_test

import (
	"testing"
	"time"

	"github.com/attestantio/vouch/util"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestTimeout(t *testing.T) {
	tests := []struct {
		name    string
		vars    map[string]string
		path    string
		timeout time.Duration
	}{
		{
			name:    "Empty",
			path:    "",
			timeout: 2 * time.Second,
		},
		{
			name:    "Root",
			path:    ".",
			timeout: 2 * time.Second,
		},
		{
			name: "TopLevel",
			vars: map[string]string{
				"timeout": "5s",
			},
			path:    "",
			timeout: 5 * time.Second,
		},
		{
			name: "SingleLevel",
			vars: map[string]string{
				"timeout": "5s",
			},
			path:    "a",
			timeout: 5 * time.Second,
		},
		{
			name: "MultiLevel",
			vars: map[string]string{
				"timeout": "5s",
			},
			path:    "a.b.c",
			timeout: 5 * time.Second,
		},
		{
			name: "Override",
			vars: map[string]string{
				"timeout":       "4s",
				"a.b.c.timeout": "5s",
			},
			path:    "a.b.c",
			timeout: 5 * time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			viper.Reset()
			viper.SetDefault("timeout", "2s")

			for k, v := range test.vars {
				viper.Set(k, v)
			}
			timeout := util.Timeout(test.path)
			require.Equal(t, test.timeout, timeout)
		})
	}
}
