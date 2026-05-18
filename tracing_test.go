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
	"testing"

	certtesting "github.com/attestantio/go-certmanager/testing"
	certmock "github.com/attestantio/go-certmanager/testing/mock"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestTracingTLSWiringHappy(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
	})

	ctx := context.Background()
	majordomo := certmock.NewMajordomo(map[string][]byte{
		"tracing-client-cert": []byte(certtesting.ClientTest01Crt),
		"tracing-client-key":  []byte(certtesting.ClientTest01Key),
	})

	viper.Set("tracing.address", "localhost:4317")
	viper.Set("tracing.client-cert", "tracing-client-cert")
	viper.Set("tracing.client-key", "tracing-client-key")

	err := initTracing(ctx, majordomo)
	require.NoError(t, err)
}

func TestTracingTLSWiringHappyWithCA(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
	})

	ctx := context.Background()
	majordomo := certmock.NewMajordomo(map[string][]byte{
		"tracing-client-cert": []byte(certtesting.ClientTest01Crt),
		"tracing-client-key":  []byte(certtesting.ClientTest01Key),
		"tracing-ca-cert":     []byte(certtesting.CACrt),
	})

	viper.Set("tracing.address", "localhost:4317")
	viper.Set("tracing.client-cert", "tracing-client-cert")
	viper.Set("tracing.client-key", "tracing-client-key")
	viper.Set("tracing.ca-cert", "tracing-ca-cert")

	err := initTracing(ctx, majordomo)
	require.NoError(t, err)
}

func TestTracingTLSMajordomoError(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
	})

	ctx := context.Background()
	majordomo := certmock.NewMajordomoWithError(errors.New("fetch failed"))

	viper.Set("tracing.address", "localhost:4317")
	viper.Set("tracing.client-cert", "tracing-client-cert")
	viper.Set("tracing.client-key", "tracing-client-key")
	viper.Set("tracing.ca-cert", "tracing-ca-cert")

	err := initTracing(ctx, majordomo)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fetch failed")
}
