// Copyright © 2024 Attestant Limited.
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
	"crypto/tls"
	"crypto/x509"
	"fmt"

	// #nosec G108
	_ "net/http/pprof"
	"os"
	"time"

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
func initTracing(ctx context.Context, majordomo majordomo.Service) error {
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
		creds, err := credentialsFromCerts(ctx, majordomo, "tracing")
		if err != nil {
			return errors.Wrap(err, "invalid TLS credentials")
		}
		driverOpts = append(driverOpts,
			otlptracegrpc.WithTLSCredentials(creds),
		)
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
	go func(ctx context.Context) {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		//nolint:contextcheck
		if err := tp.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Failed to shut down tracing")
		} else {
			log.Trace().Msg("Shut down tracing")
		}
	}(ctx)

	return nil
}

func credentialsFromCerts(ctx context.Context, majordomo majordomo.Service, base string) (credentials.TransportCredentials, error) {
	_, span := otel.Tracer("attestantio.vouch").Start(ctx, "credentialsFromCerts")
	defer span.End()

	clientCert, err := majordomo.Fetch(ctx, viper.GetString(fmt.Sprintf("%s.client-cert", base)))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain server certificate")
	}
	clientKey, err := majordomo.Fetch(ctx, viper.GetString(fmt.Sprintf("%s.client-key", base)))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain server key")
	}
	var caCert []byte
	if viper.GetString(fmt.Sprintf("%s.ca-cert", base)) != "" {
		caCert, err = majordomo.Fetch(ctx, viper.GetString(fmt.Sprintf("%s.ca-cert", base)))
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain client CA certificate")
		}
	}

	clientPair, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load client keypair")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientPair},
		MinVersion:   tls.VersionTLS13,
	}

	if caCert != nil {
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to add CA certificate")
		}
		tlsCfg.RootCAs = cp
	}

	return credentials.NewTLS(tlsCfg), nil
}
