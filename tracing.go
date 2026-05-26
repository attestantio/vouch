// Copyright © 2022 - 2026 Attestant Limited.
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

	// #nosec G108
	_ "net/http/pprof"
	"os"
	"time"

	standardclientcert "github.com/attestantio/go-certmanager/client/standard"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	majordomo "github.com/wealdtech/go-majordomo"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"google.golang.org/grpc/credentials"
)

// initTracing initialises the tracing system.
func initTracing(ctx context.Context, majordomo majordomo.Service, monitor metrics.Service) error {
	if viper.GetString("tracing.address") == "" {
		log.Debug().Msg("No tracing endpoint supplied; tracing not enabled")
		return nil
	}
	log.Info().Str("endpoint", viper.GetString("tracing.address")).Msg("Starting tracing")

	driverOpts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(viper.GetString("tracing.address")),
	}
	if viper.GetString("tracing.client-cert") != "" {
		log.Trace().Msg("Using TLS tracing connection")
		creds, err := loadTracingClientCertificates(ctx, majordomo, monitor)
		if err != nil {
			return err
		}
		driverOpts = append(driverOpts, otlptracegrpc.WithTLSCredentials(creds))
	} else {
		log.Trace().Msg("Using insecure tracing connection")
		driverOpts = append(driverOpts,
			otlptracegrpc.WithInsecure(),
		)
	}

	driver := otlptracegrpc.NewClient(driverOpts...)
	exp, err := otlptrace.New(ctx, driver)
	if err != nil {
		return errors.Wrap(err, "failed to set up OTLP exporter")
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to obtain hostname")
		hostname = "unknown"
	}
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp,
			// Vouch generates a lot of traces on startup, so increase the max queue size.
			trace.WithMaxQueueSize(16384),
		),
		trace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("Vouch"),
			semconv.ServiceInstanceIDKey.String(hostname),
			attribute.String("release", ReleaseVersion),
		)),
	)

	// Register our TracerProvider as the global so any imported
	// instrumentation in the future will default to using it.
	otel.SetTracerProvider(tp)

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Shut down cleanly on exit.
	//nolint:gosec // G118: context.Background is intentional — parent ctx is cancelled, need fresh context for shutdown.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		//nolint:contextcheck // shutdownCtx is intentionally not derived from the cancelled parent ctx.
		if err := tp.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Failed to shut down tracing")
		} else {
			log.Trace().Msg("Shut down tracing")
		}
	}()

	return nil
}

// loadTracingClientCertificates returns gRPC TLS credentials for the tracing client
// from the cert/key/CA URIs configured in viper, resolved via majordomo.
func loadTracingClientCertificates(ctx context.Context, majordomo majordomo.Service, monitor metrics.Service) (credentials.TransportCredentials, error) {
	ctx, span := otel.Tracer("attestantio.vouch").Start(ctx, "loadTracingClientCertificates")
	defer span.End()

	clientCertOpts := []standardclientcert.Parameter{
		standardclientcert.WithMajordomo(majordomo),
		standardclientcert.WithCertPEMURI(viper.GetString("tracing.client-cert")),
		standardclientcert.WithCertKeyURI(viper.GetString("tracing.client-key")),
		standardclientcert.WithMonitor(monitor),
		standardclientcert.WithName("tracing"),
	}
	// CA cert is optional; when omitted the system cert pool is used.
	if viper.GetString("tracing.ca-cert") != "" {
		clientCertOpts = append(clientCertOpts, standardclientcert.WithCACertURI(viper.GetString("tracing.ca-cert")))
	}

	clientCertMgr, err := standardclientcert.New(ctx, clientCertOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create client certificate manager for tracing")
	}

	tlsCfg, err := clientCertMgr.GetTLSConfig(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get TLS config for tracing")
	}

	return credentials.NewTLS(tlsCfg), nil
}
