package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	certtesting "github.com/attestantio/go-certmanager/testing"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

type mockMajordomo struct {
	data map[string][]byte
	err  error
}

func (m *mockMajordomo) Fetch(_ context.Context, key string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	val, exists := m.data[key]
	if !exists {
		return nil, fmt.Errorf("no value for key %s", key)
	}
	return val, nil
}

func TestTracingTLSWiringHappy(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
	})

	ctx := context.Background()
	majordomo := &mockMajordomo{
		data: map[string][]byte{
			"tracing-client-cert": []byte(certtesting.ClientTest01Crt),
			"tracing-client-key":  []byte(certtesting.ClientTest01Key),
		},
	}

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
	majordomo := &mockMajordomo{
		data: map[string][]byte{
			"tracing-client-cert": []byte(certtesting.ClientTest01Crt),
			"tracing-client-key":  []byte(certtesting.ClientTest01Key),
			"tracing-ca-cert":     []byte(certtesting.CACrt),
		},
	}

	viper.Set("tracing.address", "localhost:4317")
	viper.Set("tracing.client-cert", "tracing-client-cert")
	viper.Set("tracing.client-key", "tracing-client-key")
	viper.Set("tracing.ca-cert", "tracing-ca-cert")

	err := initTracing(ctx, majordomo)
	require.NoError(t, err)
}

func TestTracingTLSFetcherError(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
	})

	ctx := context.Background()
	majordomo := &mockMajordomo{
		err: errors.New("fetch failed"),
	}

	viper.Set("tracing.address", "localhost:4317")
	viper.Set("tracing.client-cert", "tracing-client-cert")
	viper.Set("tracing.client-key", "tracing-client-key")
	viper.Set("tracing.ca-cert", "tracing-ca-cert")

	err := initTracing(ctx, majordomo)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fetch failed")
}
