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
